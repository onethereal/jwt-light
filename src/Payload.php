<?php

namespace onethereal\JWTLight;

final class Payload
{
    private array $claims = [];

    public function getIssuer(): ?string
    {
        return $this->claims['iss'] ?? null;
    }

    public function setIssuer(string $issuer): self
    {
        $this->claims['iss'] = $issuer;
        return $this;
    }

    public function getSubject(): ?string
    {
        return $this->claims['sub'] ?? null;
    }

    public function setSubject(string $subject): self
    {
        $this->claims['sub'] = $subject;
        return $this;
    }

    public function getAudience(): ?string
    {
        return $this->claims['aud'] ?? null;
    }

    public function setAudience(string $audience): self
    {
        $this->claims['aud'] = $audience;
        return $this;
    }

    public function getExpiration(): ?int
    {
        return $this->claims['exp'] ?? null;
    }

    public function setExpiration(int $timestamp): self
    {
        $this->claims['exp'] = $timestamp;
        return $this;
    }

    public function getNotBefore(): ?int
    {
        return $this->claims['nbf'] ?? null;
    }

    public function setNotBefore(int $timestamp): self
    {
        $this->claims['nbf'] = $timestamp;
        return $this;
    }

    public function getIssuedAt(): ?int
    {
        return $this->claims['iat'] ?? null;
    }

    public function setIssuedAt(int $timestamp): self
    {
        $this->claims['iat'] = $timestamp;
        return $this;
    }

    public function getJwtId(): ?string
    {
        return $this->claims['jti'] ?? null;
    }

    public function setJwtId(string $id): self
    {
        $this->claims['jti'] = $id;
        return $this;
    }

    public function getClaim(string $key): string|int|float|bool|null|array
    {
        return $this->claims[$key] ?? null;
    }

    public function addClaim(string $key, string|int|float|bool|null|array $value): self
    {
        $this->claims[$key] = $value;
        return $this;
    }

    public function toArray(): array
    {
        return $this->claims;
    }

    public static function fromArray(array $claims): self
    {
        $payload = new self();
        $payload->claims = $claims;

        return $payload;
    }
}
