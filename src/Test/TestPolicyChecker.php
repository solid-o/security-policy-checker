<?php

declare(strict_types=1);

namespace Solido\PolicyChecker\Test;

use PHPUnit\Framework\TestCase;
use Solido\Common\Urn\Urn;
use Solido\PolicyChecker\Exception\NotSupportedException;
use Solido\PolicyChecker\PolicyCheckerInterface;
use function array_filter;
use function array_map;
use function debug_backtrace;
use function get_class;
use function is_array;
use function Safe\preg_match;
use function strlen;
use function trigger_error;
use const DEBUG_BACKTRACE_PROVIDE_OBJECT;
use const E_USER_WARNING;

class TestPolicyChecker implements PolicyCheckerInterface
{
    /** @var array<string, array<string, mixed>[]> */
    private static array $permissionsByTest = [];

    /**
     * {@inheritdoc}
     */
    public function check(Urn $subject, string $action, ?Urn $resource, array $context): bool
    {
        $testName = self::getCurrentTest();
        if ($testName === null) {
            trigger_error('Test policy checker has been used in non-test environment.', E_USER_WARNING);

            return true;
        }

        $policies = self::$permissionsByTest[$testName] ?? [];
        if (empty($policies)) {
            return true;
        }

        $resourceUrn = (string) $resource;
        $subjectUrn = (string) $subject;
        foreach ($policies as $policy) {
            $matching = array_filter(($policy['subjects'] ?? ['/.*/']), static fn (string $pattern): bool => (bool) preg_match($pattern, $subjectUrn));
            if (! $matching) {
                continue;
            }

            $matching = array_filter(($policy['resources'] ?? ['/.*/']), static fn (string $pattern): bool => (bool) preg_match($pattern, $resourceUrn));
            if (! $matching) {
                continue;
            }

            $matching = array_filter(($policy['actions'] ?? ['/.*/']), static fn (string $pattern): bool => (bool) preg_match($pattern, $action));
            if (! $matching) {
                continue;
            }

            return $policy['effect'] === self::EFFECT_ALLOW;
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function addPolicy(string $effect, $subjects, $actions, $resources, ?array $conditions = null): void
    {
        if ($conditions !== null) {
            throw new NotSupportedException('Conditions are not yet supported by Test Policy Checker.');
        }

        self::addGrant($effect, $subjects, $actions, $resources);
    }

    /**
     * Adds a policy for the current test.
     *
     * @param string|string[]|Urn|null $subjects
     * @param string|string[]|Urn|null $actions
     * @param string|string[]|Urn|null $resources
     */
    public static function addGrant(string $effect, $subjects, $actions, $resources): void
    {
        $testName = self::getCurrentTest();
        if ($testName === null) {
            return;
        }

        if ($actions === null) {
            $actions = '**';
        }

        if ($resources === null) {
            $resources = '**';
        }

        $toRegexArray = static fn ($value): array => array_map(static fn ($v) => self::globToRegex($v), is_array($value) ? $value : [$value]);

        self::$permissionsByTest[$testName][] = [
            'effect' => $effect,
            'subjects' => $toRegexArray($subjects),
            'actions' => $toRegexArray($actions),
            'resources' => $toRegexArray($resources),
        ];
    }

    private static function getCurrentTest(): ?string
    {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_PROVIDE_OBJECT);
        foreach ($backtrace as $frame) {
            if ($frame['type'] !== '->' || ! $frame['object'] instanceof TestCase) {
                continue;
            }

            $name = $frame['object']->getName();
            if (! $name) {
                continue;
            }

            return get_class($frame['object']) . '::' . $name;
        }

        return null;
    }

    /**
     * Returns a RegExp which is the equivalent of the glob pattern.
     *
     * @param string|Urn $glob
     */
    private static function globToRegex($glob): string
    {
        $glob = (string) $glob;
        if ($glob === '*') {
            // Short-circuit common case.
            // This is the only case where the "*" does not stop at first colon character.
            return '/^.*$/';
        }

        $escaping = false;
        $inCurlies = 0;
        $regex = '';

        $sizeGlob = strlen($glob);
        for ($i = 0; $i < $sizeGlob; ++$i) {
            $car = $glob[$i];
            $firstByte = $car === ':';

            if ($firstByte && isset($glob[$i + 2]) && $glob[$i + 1] . $glob[$i + 2] === '**') {
                $car = '.*';
            }

            if ($car === '.' || $car === '(' || $car === ')' || $car === '|' || $car === '+' || $car === '^' || $car === '$') {
                $regex .= '\\' . $car;
            } elseif ($car === '*') {
                $regex .= $escaping ? '\*' : '[^:]*';
            } elseif ($car === '?') {
                $regex .= $escaping ? '\?' : '[^:]';
            } elseif ($car === '{') {
                $regex .= $escaping ? '\{' : '(';
                if (! $escaping) {
                    ++$inCurlies;
                }
            } elseif ($car === '}' && $inCurlies) {
                $regex .= $escaping ? '}' : ')';
                if (! $escaping) {
                    --$inCurlies;
                }
            } elseif ($car === ',' && $inCurlies) {
                $regex .= $escaping ? ',' : '|';
            } elseif ($car === '\\') {
                if ($escaping) {
                    $regex .= '\\\\';
                    $escaping = false;
                } else {
                    $escaping = true;
                }

                continue;
            } else {
                $regex .= $car;
            }

            $escaping = false;
        }

        return '/^' . $regex . '$/';
    }
}