<?php

declare(strict_types=1);

namespace Solido\PolicyChecker\Tests;

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Prophecy\Prophecy\Revealer;
use Solido\Common\Urn\Urn;
use Solido\PolicyChecker\PolicyChecker;
use Solido\PolicyChecker\Voter\VoterInterface;

class PolicyCheckerTest extends TestCase
{
    use ProphecyTrait;

    public function testShouldIterateAllVoters(): void
    {
        $voters = [
            $this->prophesize(VoterInterface::class),
            $this->prophesize(VoterInterface::class),
            $this->prophesize(VoterInterface::class),
        ];

        $subject = new Urn('foo', 'bar');
        $resource = new Urn('foo', 'res');
        foreach ($voters as $voter) {
            $voter->vote($subject, 'SimpleAction', $resource, [])
                ->shouldBeCalled()
                ->willReturn(VoterInterface::ACCESS_ABSTAIN);
        }

        $policyChecker = new PolicyChecker((new Revealer())->reveal($voters));
        self::assertFalse($policyChecker->check($subject, 'SimpleAction', $resource, []));
    }

    public function testShouldIterateAllVotersUntilGrant(): void
    {
        $voters = [
            $this->prophesize(VoterInterface::class),
            $this->prophesize(VoterInterface::class),
            $this->prophesize(VoterInterface::class),
        ];

        $subject = new Urn('foo', 'bar');
        $resource = new Urn('foo', 'res');

        $voters[0]->vote($subject, 'SimpleAction', $resource, [])->shouldBeCalled()->willReturn(VoterInterface::ACCESS_ABSTAIN);
        $voters[1]->vote($subject, 'SimpleAction', $resource, [])->shouldBeCalled()->willReturn(VoterInterface::ACCESS_GRANTED);
        $voters[2]->vote($subject, 'SimpleAction', $resource, [])->shouldNotBeCalled();

        $policyChecker = new PolicyChecker((new Revealer())->reveal($voters));
        self::assertTrue($policyChecker->check($subject, 'SimpleAction', $resource, []));
    }

    public function testShouldIterateAllVotersUntilDeny(): void
    {
        $voters = [
            $this->prophesize(VoterInterface::class),
            $this->prophesize(VoterInterface::class),
            $this->prophesize(VoterInterface::class),
        ];

        $subject = new Urn('foo', 'bar');
        $resource = new Urn('foo', 'res');

        $voters[0]->vote($subject, 'SimpleAction', $resource, [])->shouldBeCalled()->willReturn(VoterInterface::ACCESS_ABSTAIN);
        $voters[1]->vote($subject, 'SimpleAction', $resource, [])->shouldBeCalled()->willReturn(VoterInterface::ACCESS_DENIED);
        $voters[2]->vote($subject, 'SimpleAction', $resource, [])->shouldNotBeCalled();

        $policyChecker = new PolicyChecker((new Revealer())->reveal($voters));
        self::assertFalse($policyChecker->check($subject, 'SimpleAction', $resource, []));
    }
}
