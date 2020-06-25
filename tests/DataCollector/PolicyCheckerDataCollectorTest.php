<?php declare(strict_types=1);

namespace Solido\PolicyChecker\Tests\DataCollector;

use Prophecy\PhpUnit\ProphecyTrait;
use Prophecy\Prophecy\ObjectProphecy;
use Solido\PolicyChecker\DataCollector\PolicyCheckerDataCollector;
use PHPUnit\Framework\TestCase;
use Solido\PolicyChecker\TraceablePolicyChecker;
use Symfony\Bundle\SecurityBundle\DataCollector\SecurityDataCollector;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\VarDumper\Cloner\Data;
use Symfony\Component\VarDumper\Cloner\VarCloner;

class PolicyCheckerDataCollectorTest extends TestCase
{
    use ProphecyTrait;

    /** @var ObjectProphecy|SecurityDataCollector */
    private ObjectProphecy $decorated;

    /** @var ObjectProphecy|TraceablePolicyChecker */
    private ObjectProphecy $policyChecker;

    private PolicyCheckerDataCollector $collector;

    protected function setUp(): void
    {
        $this->decorated = $this->prophesize(SecurityDataCollector::class);
        $this->policyChecker = $this->prophesize(TraceablePolicyChecker::class);
        $this->collector = new PolicyCheckerDataCollector($this->decorated->reveal(), $this->policyChecker->reveal());
    }

    public function provideCollectTraces(): iterable
    {
        yield [ [], [] ];
        yield [ [ [
            'action' => 'GetTest',
            'result' => true,
        ] ], [ [
            'action' => 'GetTest',
            'resource' => '*',
            'subject' => '',
            'context' => null,
            'result' => true,
        ] ] ];

        $cloner = new VarCloner();
        yield [ [ [
            'action' => 'GetTest',
            'resource' => 'urn:policy-checker:::test-id',
            'result' => true,
        ], [
            'action' => 'GetTest',
            'resource' => 'urn:policy-checker:::test-id',
            'context' => [
                'ip' => '127.0.0.1',
            ],
            'result' => false,
        ] ], [ [
            'action' => 'GetTest',
            'resource' => 'urn:policy-checker:::test-id',
            'subject' => '',
            'context' => null,
            'result' => true,
        ], [
            'action' => 'GetTest',
            'resource' => 'urn:policy-checker:::test-id',
            'subject' => '',
            'context' => $cloner->cloneVar([
                'ip' => '127.0.0.1',
            ]),
            'result' => false,
        ] ] ];
    }

    /**
     * @dataProvider provideCollectTraces
     */
    public function testCollect(array $traces, array $permissions): void
    {
        $request = new Request();
        $response = new Response();

        $this->decorated->collect($request, $response, null)->shouldBeCalled();
        $this->policyChecker->getTraces()->willReturn($traces);

        $this->collector->collect($request, $response, null);

        self::assertEquals($permissions, $this->collector->getPolicyPermissions());
    }
}
