<?php

namespace onethereal\JWTLight\helpers;

use onethereal\JWTLight\enum\HashAlgorithmEnum;

class Utils
{
    public static function base64UrlEncode(string $data): string
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    public static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * @param non-empty-string $encodedHeader
     * @param non-empty-string $encodedPayload
     * @param non-empty-string $secretKey
     * @param HashAlgorithmEnum $hashAlgorithm
     * @return non-empty-string
     */
    public static function createSignature(
        string            $encodedHeader,
        string            $encodedPayload,
        string            $secretKey,
        HashAlgorithmEnum $hashAlgorithm,
    ): string
    {
        $signingInput = sprintf('%s.%s', $encodedHeader, $encodedPayload);

        return match ($hashAlgorithm) {
            HashAlgorithmEnum::HS256 => self::base64UrlEncode(hash_hmac('sha256', $signingInput, $secretKey, true)),
            default => throw new \InvalidArgumentException('Unsupported algorithm'),
        };
    }

    public static function verifySignature(string $signature, string $expectedSignature): bool
    {
        return hash_equals(self::base64UrlDecode($signature), self::base64UrlDecode($expectedSignature));
    }
}
