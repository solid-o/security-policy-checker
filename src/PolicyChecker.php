<?php

declare(strict_types=1);

namespace Solido\PolicyChecker;

use Solido\Common\Urn\Urn;
use Solido\PolicyChecker\Exception\NotSupportedException;
use Solido\PolicyChecker\Voter\VoterInterface;
use function array_map;

class PolicyChecker implements PolicyCheckerInterface
{
    /** @var iterable<VoterInterface> */
    private iterable $voters;

    /**
     * @param iterable<VoterInterface> $voters
     */
    public function __construct(iterable $voters)
    {
        $this->voters = $voters;
    }

    /**
     * {@inheritdoc}
     */
    public function addPolicy(string $effect, $subjects, $actions, $resources, ?array $conditions = null): void
    {
        if ($subjects === null) {
            $subjects = '**';
        }

        if ($actions === null) {
            $actions = '**';
        }

        if ($resources === null) {
            $resources = '**';
        }

        $added = false;
        foreach ($this->voters as $voter) {
            if (! $voter->supportsAddPolicy()) {
                continue;
            }

            try {
                $voter->addPolicy(
                    $effect,
                    array_map(static fn($v) => (string) $v, (array) $subjects),
                    array_map(static fn($v) => (string) $v, (array) $actions),
                    array_map(static fn($v) => (string) $v, (array) $resources),
                    $conditions ?? []
                );
            } catch (NotSupportedException $e) {
                // @ignoreException
            }

            $added = true;
        }

        if (! $added) {
            throw new NotSupportedException('No voter is able to add the specified policy');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function check(Urn $subject, string $action, ?Urn $resource, array $context): bool
    {
        foreach ($this->voters as $voter) {
            $vote = $voter->vote($subject, $action, $resource, $context);
            if ($vote !== VoterInterface::ACCESS_ABSTAIN) {
                return $vote === VoterInterface::ACCESS_GRANTED;
            }
        }

        return false;
    }
}
