<?php

namespace onethereal\JWTLight\cmd;

use onethereal\JWTLight\enum\EnvEnum;

final readonly class Installer
{
    public static function install(): void
    {
        $envFile = getcwd() . '/.env';
        $jwtLightSecretName = EnvEnum::SECRET_KEY->value;
        $envTemplate = "### onethereal/JWTLight\n$jwtLightSecretName=\n### <onethereal/JWTLight\n";

        if (!file_exists($envFile)) {
            file_put_contents($envFile, $envTemplate);
            return;
        }

        $envContent = file_get_contents($envFile);

        if (!str_contains($envContent, $jwtLightSecretName)) {
            file_put_contents($envFile, "\n" . $envTemplate, FILE_APPEND);
        }
    }
}
