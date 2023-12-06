<?php

declare(strict_types=1);

namespace Solido\PolicyChecker;

use Solido\Common\Urn\Urn;

interface PolicyCheckerInterface
{
    public const EFFECT_ALLOW = 'allow';
    public const EFFECT_DENY = 'deny';

    /**
     * Adds a policy to the policy checker engine.
     * If adding is not a supported operation, the implementation MUST throw an
     * instance of {@link NotSupportedException}.
     *
     * @param string|string[]|Urn|null $subjects
     * @param string|string[]|Urn|null $actions
     * @param string|string[]|Urn|null $resources
     * @param array<mixed, mixed>|null $conditions
     */
    public function addPolicy(string $effect, string|array|Urn|null $subjects, string|array|Urn|null $actions, string|array|Urn|null $resources, array|null $conditions = null): void;

    /**
     * Checks if the given *subject* is allow to execution *action* on the given *resource*.
     *
     * Subject and resource MUST be theirs urn representation to allow
     * glob and regex checking in keto engine.
     *
     * @param array<string, string|string[]> $context
     */
    public function check(Urn $subject, string $action, Urn|null $resource, array $context): bool;
}
