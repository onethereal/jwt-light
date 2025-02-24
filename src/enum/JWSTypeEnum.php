<?php

namespace onethereal\JWTLight\enum;

enum JWSTypeEnum: string
{
    case JWT = 'JWT';
    case JWE = 'JWE';

    public static function allowedCases(): array
    {
        return [
            self::JWT,
        ];
    }
}
