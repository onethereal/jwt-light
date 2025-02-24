<?php

namespace onethereal\JWTLight\enum;

enum HashAlgorithmEnum: string
{
    case HS256 = 'HS256';
    case HS512 = 'HS512';

    public static function fromValue(mixed $alg): self
    {
        return match ($alg) {
            self::HS256->value => self::HS256,
            self::HS512->value => self::HS512,
            default => throw new \InvalidArgumentException('Unsupported algorithm'),
        };
    }

    public static function allowedCases(): array
    {
        return [
            self::HS256,
        ];
    }
}
