<?php

declare(strict_types=1);

namespace Solido\PolicyChecker\DataCollector;

use Error;
use Psr\Log\LoggerAwareTrait;
use ReflectionClass;
use Solido\PolicyChecker\TraceablePolicyChecker;
use Symfony\Bundle\SecurityBundle\DataCollector\SecurityDataCollector;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Symfony\Component\HttpKernel\DataCollector\LateDataCollectorInterface;
use Symfony\Component\HttpKernel\Log\DebugLoggerInterface;
use Symfony\Component\VarDumper\Cloner\Data;
use Throwable;

use function assert;
use function is_array;
use function method_exists;
use function Safe\sprintf;

class PolicyCheckerDataCollector extends DataCollector implements LateDataCollectorInterface
{
    use LoggerAwareTrait;

    private string $baseTemplate = '@Security/Collector/security.html.twig';

    public function __construct(private SecurityDataCollector $decorated, private TraceablePolicyChecker $policyChecker)
    {
    }

    public function collect(Request $request, Response $response, Throwable|null $exception = null): void
    {
        $this->decorated->collect($request, $response, $exception);

        $permissions = [];
        foreach ($this->policyChecker->getTraces() as $log) {
            $action = $log['action'] ?? null;
            $subject = $log['subject'] ?? null;

            $permissions[] = [
                'action' => $action,
                'resource' => (string) ($log['resource'] ?? null) ?: '*',
                'subject' => (string) $subject,
                'context' => $log['context'] ?? null,
                'result' => $log['result'],
            ];
        }

        $this->data = ['policy_permissions' => $permissions];
    }

    public function getName(): string
    {
        return $this->getDecoratedService()->getName();
    }

    public function setBaseTemplate(string $baseTemplate): void
    {
        $this->baseTemplate = $baseTemplate;
    }

    public function getBaseTemplate(): string
    {
        return $this->baseTemplate;
    }

    /** @param mixed[] $arguments */
    public function __call(string $name, array $arguments): mixed
    {
        $decorated = $this->getDecoratedService();

        $getter = 'get' . $name;
        $hasser = 'has' . $name;
        $isser = 'is' . $name;

        if (method_exists($decorated, $getter)) {
            return $decorated->$getter(...$arguments);
        }

        if (method_exists($decorated, $hasser)) {
            return $decorated->$hasser(...$arguments);
        }

        if (method_exists($decorated, $isser)) {
            return $decorated->$isser(...$arguments);
        }

        if (method_exists($decorated, $name)) {
            return $decorated->$name(...$arguments);
        }

        throw new Error(sprintf('Call to undefined method %s::%s', static::class, $name));
    }

    public function reset(): void
    {
        if ($this->logger instanceof DebugLoggerInterface) {
            $this->logger->clear();
        }

        $this->data = [];
        $this->getDecoratedService()->reset();
    }

    public function lateCollect(): void
    {
        assert(is_array($this->data) && is_array($this->decorated->data));
        $this->data = $this->cloneVar($this->data + $this->decorated->data);
    }

    /** @return array<string, mixed>[]|Data|null */
    public function getPolicyPermissions(): array|Data|null
    {
        return $this->data['policy_permissions'] ?? null;
    }

    private function getDecoratedService(): SecurityDataCollector
    {
        if (! isset($this->decorated) && $this->data instanceof Data) {
            // We are in profiler and this instance has been deserialized.
            $reflection = new ReflectionClass(SecurityDataCollector::class);
            $this->decorated = $reflection->newInstanceWithoutConstructor();
            $this->decorated->data = $this->data;
        }

        return $this->decorated;
    }
}
