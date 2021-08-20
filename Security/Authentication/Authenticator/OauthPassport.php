<?php

namespace FOS\OAuthServerBundle\Security\Authentication\Authenticator;

use FOS\OAuthServerBundle\Security\Authentication\Token\OAuthToken;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportTrait;

class OauthPassport implements PassportInterface
{
    use PassportTrait;

    private OAuthToken $oauthToken;

    public function __construct(OAuthToken $oauthToken)
    {
        $this->oauthToken = $oauthToken;
    }

    public function getOauthToken(): OAuthToken
    {
        return $this->oauthToken;
    }
}
