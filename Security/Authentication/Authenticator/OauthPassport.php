<?php

namespace FOS\OAuthServerBundle\Security\Authentication\Authenticator;

use FOS\OAuthServerBundle\Security\Authentication\Token\OAuthToken;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportTrait;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class OauthPassport extends SelfValidatingPassport
{
    const ATTRIBUTE_OAUTH_TOKEN = ' oauth_token';

    public function getOauthToken(): OAuthToken
    {
        return $this->getAttribute(self::ATTRIBUTE_OAUTH_TOKEN);
    }
}
