<?php

declare(strict_types=1);

namespace Solido\PolicyChecker;

use Psr\Log\LoggerInterface;
use Solido\Common\Urn\Urn;
use Symfony\Contracts\Service\ResetInterface;

class TraceablePolicyChecker implements PolicyCheckerInterface, ResetInterface
{
    /**
     * @var array<bool|string|array<string, string|string[]>>
     * @phpstan-var list<array{action: string, resource: string, subject: string, context: array<string, string|string[]>, result: bool}>
     */
    private array $trace = [];

    public function __construct(private PolicyCheckerInterface $decorated, private LoggerInterface $logger)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function addPolicy(string $effect, $subject, $action, $resource, array|null $conditions = null): void
    {
        $this->decorated->addPolicy($effect, $subject, $action, $resource, $conditions);
    }

    /**
     * {@inheritDoc}
     */
    public function check(Urn $subject, string $action, Urn|null $resource, array $context): bool
    {
        $result = $this->decorated->check($subject, $action, $resource, $context);
        $trace = [
            'action' => $action,
            'resource' => (string) $resource,
            'subject' => (string) $subject,
            'context' => $context,
            'result' => $result,
        ];

        $this->logger->debug('Checking if "{{ action }}" is allowed on {{ resource }} for {{ subject }}', $trace);
        $this->trace[] = $trace;

        return $result;
    }

    /**
     * @return array<string, array<string|bool|array<string, string|string[]>>>
     * @phpstan-return list<array{action?: string, resource?: string, subject?: string, context?: array<string, string|string[]>, result: bool}>
     */
    public function getTraces(): array
    {
        return $this->trace;
    }

    public function reset(): void
    {
        $this->trace = [];
    }
}
