<?php

declare(strict_types=1);

namespace Solido\PolicyChecker\Voter;

use Solido\Common\Urn\Urn;

interface VoterInterface
{
    public const ACCESS_GRANTED = 1;
    public const ACCESS_ABSTAIN = 0;
    public const ACCESS_DENIED = -1;

    /**
     * Returns the vote for the given parameters.
     *
     * This method must return one of the following constants:
     * ACCESS_GRANTED, ACCESS_DENIED, or ACCESS_ABSTAIN.
     *
     * @param array<string, string|string[]> $context
     */
    public function vote(Urn $subject, string $action, ?Urn $resource, array $context): int;

    /**
     * Whether this voter supports adding policies.
     */
    public function supportsAddPolicy(): bool;

    /**
     * Adds a policy for this voter.
     * If adding is not a supported operation, the implementation MUST throw an
     * instance of {@link NotSupportedException}.
     *
     * @param string[] $subjects
     * @param string[] $actions
     * @param string[] $resources
     * @param array<mixed, mixed> $conditions
     */
    public function addPolicy(string $effect, array $subjects, array $actions, array $resources, array $conditions): void;
}
