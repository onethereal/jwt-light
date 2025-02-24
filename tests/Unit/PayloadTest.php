<?php

namespace onethereal\JWTLight\tests\Unit;

use onethereal\JWTLight\Payload;
use PHPUnit\Framework\TestCase;

/**
 * @covers \onethereal\JWTLight\Payload
 */
class PayloadTest extends TestCase
{
    private Payload $payload;

    protected function setUp(): void
    {
        $this->payload = new Payload();
    }

    public function testSetAndGetIssuer(): void
    {
        $this->payload->setIssuer('foo');
        $this->assertEquals('foo', $this->payload->getIssuer());
    }

    public function testSetAndGetSubject(): void
    {
        $this->payload->setSubject('Tyler Durden');
        $this->assertEquals('Tyler Durden', $this->payload->getSubject());
    }

    public function testSetAndGetAudience(): void
    {
        $this->payload->setAudience('foo.bar');
        $this->assertEquals('foo.bar', $this->payload->getAudience());
    }

    public function testSetAndGetExpiration(): void
    {
        $timestamp = time() + 3600;
        $this->payload->setExpiration($timestamp);
        $this->assertEquals($timestamp, $this->payload->getExpiration());
    }

    public function testSetAndGetNotBefore(): void
    {
        $timestamp = time() - 3600;
        $this->payload->setNotBefore($timestamp);
        $this->assertEquals($timestamp, $this->payload->getNotBefore());
    }

    public function testSetAndGetIssuedAt(): void
    {
        $timestamp = time();
        $this->payload->setIssuedAt($timestamp);
        $this->assertEquals($timestamp, $this->payload->getIssuedAt());
    }

    public function testSetAndGetJwtId(): void
    {
        $id = uniqid(prefix: 'jwt', more_entropy: true);
        $this->payload->setJwtId($id);
        $this->assertEquals($id, $this->payload->getJwtId());
    }

    public function testSetAndGetCustomClaim(): void
    {
        $this->payload->addClaim('role', 'admin');
        $this->assertEquals('admin', $this->payload->getClaim('role'));
    }

    public function testGetNonExistentClaimReturnsNull(): void
    {
        $this->assertNull($this->payload->getClaim('non_existent'));
        $this->assertNull($this->payload->getIssuer());
    }

    public function testToArrayReturnsAllClaims(): void
    {
        $this->payload
            ->setIssuer('foo.bar')
            ->setSubject('Tyler Durden')
            ->addClaim('role', 'admin');

        $expected = [
            'iss' => 'foo.bar',
            'sub' => 'Tyler Durden',
            'role' => 'admin',
        ];

        $this->assertEquals($expected, $this->payload->toArray());
    }

    public function testFromArrayLoadsClaims(): void
    {
        $claims = [
            'iss' => 'foo.bar',
            'sub' => 'Tyler Durden',
            'exp' => time() + 3600,
            'custom' => 'value',
        ];

        $payload = Payload::fromArray($claims);

        $this->assertEquals('foo.bar', $payload->getIssuer());
        $this->assertEquals('Tyler Durden', $payload->getSubject());
        $this->assertEquals($claims['exp'], $payload->getExpiration());
        $this->assertEquals('value', $payload->getClaim('custom'));
    }
}
