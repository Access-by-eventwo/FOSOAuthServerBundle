<?php

declare(strict_types=1);

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Model;

use Symfony\Component\Security\Core\User\UserInterface;

class Token implements TokenInterface
{
    /**
     * @var int
     */
    protected $id;

    /**
     * @var ClientInterface
     */
    protected $client;

    /**
     * @var string
     */
    protected $token;

    /**
     * @var int
     */
    protected $expiresAt;

    /**
     * @var string
     */
    protected $scope;

    /**
     * @var UserInterface
     */
    protected $user;

    public function getId(): int
    {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function getClientId(): string
    {
        return $this->getClient()->getPublicId();
    }

    /**
     * {@inheritdoc}
     */
    public function setExpiresAt($timestamp): void
    {
        $this->expiresAt = $timestamp;
    }

    /**
     * {@inheritdoc}
     */
    public function getExpiresAt(): int
    {
        return $this->expiresAt;
    }

    /**
     * {@inheritdoc}
     */
    public function getExpiresIn(): int
    {
        if ($this->expiresAt) {
            return $this->expiresAt - time();
        }

        return PHP_INT_MAX;
    }

    /**
     * {@inheritdoc}
     */
    public function hasExpired(): bool
    {
        if ($this->expiresAt) {
            return time() > $this->expiresAt;
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function setToken($token): void
    {
        $this->token = $token;
    }

    /**
     * {@inheritdoc}
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * {@inheritdoc}
     */
    public function setScope($scope): void
    {
        $this->scope = $scope;
    }

    /**
     * {@inheritdoc}
     */
    public function getScope(): ?string
    {
        return $this->scope;
    }

    /**
     * {@inheritdoc}
     */
    public function setUser(UserInterface $user): void
    {
        $this->user = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getUser(): ?UserInterface
    {
        return $this->user;
    }

    /**
     * {@inheritdoc}
     */
    public function getData(): mixed
    {
        return $this->getUser();
    }

    /**
     * {@inheritdoc}
     */
    public function setClient(ClientInterface $client): void
    {
        $this->client = $client;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient(): ClientInterface
    {
        return $this->client;
    }
}
