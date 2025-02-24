<?php

namespace onethereal\JWTLight;

use onethereal\JWTLight\enum\{EnvEnum, HashAlgorithmEnum, JWSTypeEnum};
use onethereal\JWTLight\exceptions\InvalidTokenException;
use onethereal\JWTLight\helpers\Utils;
use InvalidArgumentException;
use JsonException;

final class JWT
{
    public function __construct(private ?string $secretKey = null)
    {
        $jwtLightSecretKeyName = EnvEnum::SECRET_KEY->value;
        $fromGlobalEnv = $_ENV[$jwtLightSecretKeyName] ?? null;
        $this->secretKey = $secretKey ?? $fromGlobalEnv
            ?: throw new InvalidArgumentException(message: "Secret key must be provided via argument or $jwtLightSecretKeyName environment variable");
    }

    /**
     * Encodes a payload into a JWT token.
     *
     * @param array|Payload $payload Data to encode
     * @param HashAlgorithmEnum $hashAlgorithm
     * @return string
     * @throws JsonException
     * @throws InvalidArgumentException
     */
    public function encode(array|Payload $payload, HashAlgorithmEnum $hashAlgorithm): string
    {
        if (empty($this->secretKey)) {
            throw new InvalidArgumentException(message: 'Secret key cannot be empty');
        }

        $header = [
            'alg' => $hashAlgorithm->value,
            'typ' => JWSTypeEnum::JWT->value,
        ];

        $payloadArray = $payload instanceof Payload ? $payload->toArray() : $payload;

        if (empty($payloadArray)) {
            throw new InvalidArgumentException('Payload cannot be empty');
        }

        $encodedHeader = Utils::base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR));
        $encodedPayload = Utils::base64UrlEncode(json_encode($payloadArray, JSON_THROW_ON_ERROR));
        $signature = Utils::createSignature($encodedHeader, $encodedPayload, $this->secretKey, $hashAlgorithm);

        return sprintf('%s.%s.%s', $encodedHeader, $encodedPayload, $signature);
    }

    /**
     * Decodes a JWT token into its payload.
     *
     * @param non-empty-string $token
     * @return Payload
     * @throws InvalidTokenException
     */
    public function decode(string $token): Payload
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new InvalidTokenException('Invalid token format');
        }

        [$encodedHeader, $encodedPayload, $signature] = $parts;

        try {
            $header = json_decode(Utils::base64UrlDecode($encodedHeader), true, 512, JSON_THROW_ON_ERROR);
            $payloadArray = json_decode(Utils::base64UrlDecode($encodedPayload), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidTokenException(message: 'Failed to decode token parts');
        }

        $expectedSignature = Utils::createSignature(
            $encodedHeader,
            $encodedPayload,
            $this->secretKey,
            HashAlgorithmEnum::fromValue($header['alg'])
        );

        if (!Utils::verifySignature($signature, $expectedSignature)) {
            throw new InvalidTokenException('Invalid token signature');
        }

        return Payload::fromArray($payloadArray);
    }
}
