<?php

namespace onethereal\JWTLight\tests\Unit;

use onethereal\JWTLight\enum\HashAlgorithmEnum;
use onethereal\JWTLight\helpers\Utils;
use PHPUnit\Framework\TestCase;

/**
 * @covers \onethereal\JWTLight\helpers\Utils
 */
class UtilsTest extends TestCase
{
    public function testBase64UrlEncode(): void
    {
        $data = 'Hello, World!';
        $encoded = Utils::base64UrlEncode($data);
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
        $this->assertStringNotContainsString('=', $encoded);
    }

    public function testBase64UrlDecode(): void
    {
        $data = 'Hello, World!';
        $encoded = Utils::base64UrlEncode($data);
        $decoded = Utils::base64UrlDecode($encoded);
        $this->assertEquals($data, $decoded);
    }

    public function testCreateSignature(): void
    {
        $header = '{"alg":"HS256","typ":"JWT"}';
        $payload = '{"sub":"1234567890","name":"John Doe","iat":1516239022}';
        $secretKey = 'your-256-bit-secret';
        $encodedHeader = Utils::base64UrlEncode($header);
        $encodedPayload = Utils::base64UrlEncode($payload);

        $signature = Utils::createSignature($encodedHeader, $encodedPayload, $secretKey, HashAlgorithmEnum::HS256);
        $this->assertNotEmpty($signature);
    }

    public function testVerifySignature(): void
    {
        $header = '{"alg":"HS256","typ":"JWT"}';
        $payload = '{"sub":"1234567890","name":"John Doe","iat":1516239022}';
        $secretKey = 'your-256-bit-secret';
        $encodedHeader = Utils::base64UrlEncode($header);
        $encodedPayload = Utils::base64UrlEncode($payload);

        $signature = Utils::createSignature($encodedHeader, $encodedPayload, $secretKey, HashAlgorithmEnum::HS256);
        $this->assertTrue(Utils::verifySignature($signature, $signature));
    }

    public function testVerifySignatureWithInvalidSignature(): void
    {
        $header = '{"alg":"HS256","typ":"JWT"}';
        $payload = '{"sub":"1234567890","name":"John Doe","iat":1516239022}';
        $secretKey = 'your-256-bit-secret';
        $encodedHeader = Utils::base64UrlEncode($header);
        $encodedPayload = Utils::base64UrlEncode($payload);

        $signature = Utils::createSignature($encodedHeader, $encodedPayload, $secretKey, HashAlgorithmEnum::HS256);
        $invalidSignature = 'invalid_signature';
        $this->assertFalse(Utils::verifySignature($signature, $invalidSignature));
    }
}
