<?php declare(strict_types=1);

namespace Solido\PolicyChecker\Tests\Test;

use Solido\Common\Urn\Urn;
use Solido\PolicyChecker\PolicyCheckerInterface;
use Solido\PolicyChecker\Test\TestPolicyChecker;
use PHPUnit\Framework\TestCase;

class TestPolicyCheckerTest extends TestCase
{
    private TestPolicyChecker $policyChecker;

    protected function setUp(): void
    {
        $this->policyChecker = new TestPolicyChecker();
    }

    public function testCheckForCurrentTest(): void
    {
        $subject = new Urn('test-id', 'test-class');

        TestPolicyChecker::addGrant(PolicyCheckerInterface::EFFECT_ALLOW, $subject, 'GetTest1', '*');
        TestPolicyChecker::addGrant(PolicyCheckerInterface::EFFECT_ALLOW, $subject, 'GetTestSomeResources', 'urn:::::some-class:test-*');
        TestPolicyChecker::addGrant(PolicyCheckerInterface::EFFECT_ALLOW, $subject, 'GetTestSomeResources2', 'urn:::::{foo,bar}-class:*');
        TestPolicyChecker::addGrant(PolicyCheckerInterface::EFFECT_ALLOW, '*', 'AllowAllSubjects', '*');

        self::assertTrue($this->policyChecker->check($subject, 'GetTest1', null, []));
        self::assertFalse($this->policyChecker->check($subject, 'GetTest2', null, []));
        self::assertFalse($this->policyChecker->check(new Urn('test-id-2', 'test-class'), 'GetTest1', null, []));

        self::assertTrue($this->policyChecker->check($subject, 'AllowAllSubjects', null, []));
        self::assertTrue($this->policyChecker->check(new Urn('test-id-2', 'test-class'), 'AllowAllSubjects', null, []));
        self::assertTrue($this->policyChecker->check(new Urn('foo-bar', 'foo-class'), 'AllowAllSubjects', null, []));

        self::assertFalse($this->policyChecker->check($subject, 'GetTestSomeResources', new Urn('not-test-foo', 'some-class'), []));
        self::assertTrue($this->policyChecker->check($subject, 'GetTestSomeResources', new Urn('test-foo', 'some-class'), []));

        self::assertFalse($this->policyChecker->check($subject, 'GetTestSomeResources2', new Urn('test-foo', 'some-class'), []));
        self::assertTrue($this->policyChecker->check($subject, 'GetTestSomeResources2', new Urn('test-foo', 'foo-class'), []));
        self::assertFalse($this->policyChecker->check($subject, 'GetTestSomeResources2', new Urn('test-foo', 'foo2-class'), []));
    }
}
