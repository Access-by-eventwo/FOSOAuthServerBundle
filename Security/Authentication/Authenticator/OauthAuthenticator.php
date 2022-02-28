<?php

namespace FOS\OAuthServerBundle\Security\Authentication\Authenticator;

use FOS\OAuthServerBundle\Security\Authentication\Token\OAuthToken;
use FOS\OAuthServerBundle\Security\Core\User\OAuthUser;
use OAuth2\OAuth2;
use OAuth2\OAuth2AuthenticateException;
use OAuth2\OAuth2ServerException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\PreAuthenticatedUserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CustomCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class OauthAuthenticator extends AbstractAuthenticator
{
    /**
     * @var OAuth2
     */
    protected $serverService;

    /**
     * @var UserCheckerInterface
     */
    protected $userChecker;

    public function __construct(OAuth2 $serverService, UserCheckerInterface $userChecker)
    {
        $this->serverService = $serverService;
        $this->userChecker = $userChecker;
    }

    public function supports(Request $request): ?bool
    {
        return true;
    }

    public function authenticate(Request $request): PassportInterface
    {
        try {
            $tokenString = $this->serverService->getBearerToken($request, true);

            // TODO: this is nasty, create a proper interface here
            /** @var OAuthToken&TokenInterface&\OAuth2\Model\IOAuth2AccessToken $accessToken */
            $accessToken = $this->serverService->verifyAccessToken($tokenString);

            $scope = $accessToken->getScope();
            $user = $accessToken->getUser();

            if (null !== $user) {
                try {
                    $this->userChecker->checkPreAuth($user);
                } catch (AccountStatusException $e) {
                    throw new OAuth2AuthenticateException(
                        Response::HTTP_UNAUTHORIZED,
                        OAuth2::TOKEN_TYPE_BEARER,
                        $this->serverService->getVariable(OAuth2::CONFIG_WWW_REALM),
                        'access_denied',
                        $e->getMessage()
                    );
                }
            }

            $roles = (null !== $user) ? $user->getRoles() : [];

            if (!empty($scope)) {
                foreach (explode(' ', $scope) as $role) {
                    $roles[] = 'ROLE_' . mb_strtoupper($role);
                }
            }

            $roles = array_unique($roles, SORT_REGULAR);

            $token = new OAuthToken($roles);
            $token->setToken($tokenString);

            if (null !== $user) {
                try {
                    $this->userChecker->checkPostAuth($user);
                } catch (AccountStatusException $e) {
                    throw new OAuth2AuthenticateException(
                        Response::HTTP_UNAUTHORIZED,
                        OAuth2::TOKEN_TYPE_BEARER,
                        $this->serverService->getVariable(OAuth2::CONFIG_WWW_REALM),
                        'access_denied',
                        $e->getMessage()
                    );
                }

                $token->setUser($user);
            }

            if (null === $user) {
                $user = new OAuthUser($tokenString);
                $user->setRoles($roles);

                $token->setUser($user);
            }

            $passport = new OauthPassport(
                new UserBadge($tokenString),
                [
                    new PreAuthenticatedUserBadge()
                ]
            );
            $passport->setAttribute(OauthPassport::ATTRIBUTE_OAUTH_TOKEN, $token);

            return $passport;
        } catch (OAuth2ServerException $e) {
            throw new AuthenticationException('OAuth2 authentication failed', 0, $e);
        }
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return null;
    }

    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        if (false === $passport instanceof OauthPassport) {
            throw new AuthenticationException('OAuth2 authentication failed', 0, $e);
        }

        return $passport->getOauthToken();
    }
}
