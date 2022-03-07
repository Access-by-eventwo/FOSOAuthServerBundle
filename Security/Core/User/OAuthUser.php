<?php

namespace FOS\OAuthServerBundle\Security\Core\User;

use Symfony\Component\Security\Core\User\UserInterface;

class OAuthUser implements UserInterface
{
    private string $tokenString;
    private array $roles = [];

    public function __construct(string $tokenString)
    {
        $this->tokenString = $tokenString;
    }

    public function getTokenString(): string
    {
        return $this->tokenString;
    }

    public function setRoles(array $roles): void
    {
        $this->roles = $roles;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getPassword(): ?string
    {
        return null;
    }

    public function getSalt(): ?string
    {
        return null;
    }

    public function eraseCredentials(): void
    {
    }

    public function getUsername(): string
    {
        return $this->tokenString;
    }

    public function getUserIdentifier(): string
    {
        return $this->tokenString;
    }
}
