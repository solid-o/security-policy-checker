<?php

declare(strict_types=1);

namespace Solido\PolicyChecker;

use Psr\Log\LoggerInterface;
use Solido\Common\Urn\Urn;
use Symfony\Contracts\Service\ResetInterface;

class TraceablePolicyChecker implements PolicyCheckerInterface, ResetInterface
{
    private PolicyCheckerInterface $decorated;
    private LoggerInterface $logger;

    /**
     * @var array<bool|string>
     * @phpstan-var array<array{action: string, resource: string, subject: string, result: bool}>
     */
    private array $trace = [];

    public function __construct(PolicyCheckerInterface $decorated, LoggerInterface $logger)
    {
        $this->decorated = $decorated;
        $this->logger = $logger;
    }

    /**
     * {@inheritDoc}
     */
    public function addPolicy(string $effect, $subject, $action, $resource, ?array $conditions = null): void
    {
        $this->decorated->addPolicy($effect, $subject, $action, $resource, $conditions);
    }

    /**
     * {@inheritdoc}
     */
    public function check(Urn $subject, string $action, ?Urn $resource, array $context): bool
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
     * @return array<string, array<string|bool>>
     * @phpstan-return array<string, array{action?: string, resource?: string, subject?: string, context?: array, result: bool}>
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
