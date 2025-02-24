<?php

namespace onethereal\JWTLight\exceptions;

final class InvalidTokenException extends JWTException
{
    public function __construct(string $message = 'Invalid token format')
    {
        parent::__construct(message: $message);
    }
}
