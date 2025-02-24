<?php

namespace onethereal\JWTLight\tests\Unit;

use onethereal\JWTLight\enum\{EnvEnum, HashAlgorithmEnum};
use onethereal\JWTLight\{JWT, Payload};
use onethereal\JWTLight\exceptions\InvalidTokenException;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;
use JsonException;

/**
 * @covers \onethereal\JWTLight\JWT
 */
class JWTTest extends TestCase
{
    private JWT $jwt;
    private string $secretKey = 'not-a-real-secret-key';

    protected function setUp(): void
    {
        $this->jwt = new JWT($this->secretKey);
    }

    /**
     * @throws InvalidTokenException
     * @throws JsonException
     */
    public function testEncodeAndDecodeWithArray(): void
    {
        $payload = ['user_id' => 123, 'username' => 'testUser'];
        $token = $this->jwt->encode($payload, HashAlgorithmEnum::HS256);
        $decodedPayload = $this->jwt->decode($token);

        $this->assertInstanceOf(Payload::class, $decodedPayload);
        $this->assertEquals($payload, $decodedPayload->toArray());
    }

    /**
     * @throws InvalidTokenException
     * @throws JsonException
     */
    public function testEncodeAndDecodeWithPayload(): void
    {
        $payload = (new Payload())
            ->setIssuer('https://example.com')
            ->setSubject('user123')
            ->setExpiration(time() + 3600)
            ->setClaim('role', 'admin');

        $token = $this->jwt->encode($payload, HashAlgorithmEnum::HS256);
        $decodedPayload = $this->jwt->decode($token);

        $this->assertInstanceOf(Payload::class, $decodedPayload);
        $this->assertEquals('https://example.com', $decodedPayload->getIssuer());
        $this->assertEquals('user123', $decodedPayload->getSubject());
        $this->assertEquals($payload->getExpiration(), $decodedPayload->getExpiration());
        $this->assertEquals('admin', $decodedPayload->getClaim('role'));
    }

    public function testDecodeInvalidToken(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Failed to decode token parts');

        $this->jwt->decode('invalid.token.here');
    }

    /**
     * @throws JsonException
     */
    public function testDecodeTokenWithInvalidSignature(): void
    {
        $payload = ['user_id' => 123, 'username' => 'test_user'];
        $token = $this->jwt->encode($payload, HashAlgorithmEnum::HS256);

        $tokenParts = explode('.', $token);
        $tokenParts[2] = 'invalid_signature';
        $invalidToken = implode('.', $tokenParts);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid token signature');

        $this->jwt->decode($invalidToken);
    }

    /**
     * @throws JsonException
     * @throws InvalidTokenException
     */
    public function testEncodeWithDifferentAlgorithms(): void
    {
        $payload = ['user_id' => 123, 'username' => 'test_user'];

        foreach (HashAlgorithmEnum::allowedCases() as $algorithm) {
            $token = $this->jwt->encode($payload, $algorithm);
            $decodedPayload = $this->jwt->decode($token);

            $this->assertEquals($payload, $decodedPayload->toArray());
        }
    }

    /**
     * @throws JsonException
     */
    public function testEncodeWithEmptyPayloadThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Payload cannot be empty');

        $this->jwt->encode([], HashAlgorithmEnum::HS256);
    }

    public function testEncodeWithEmptySecretKeyThrowsException(): void
    {
        $jwtLightSecretKeyName = EnvEnum::SECRET_KEY->value;
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Secret key must be provided via argument or $jwtLightSecretKeyName environment variable");

        new JWT('');
    }
}
