<?php

namespace Acme\DemoBundle\Security;

use Symfony\Component\Security\Core\Authentication\SimpleHttpAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

class ApiKeyAuthenticator implements SimpleHttpAuthenticatorInterface, UserProviderInterface, AuthenticationFailureHandlerInterface, AuthenticationSuccessHandlerInterface
{
    /* -- helper/own methods -- */

    public function loadUserByApiKey($apikey)
    {
        // load users from flat file user "database"
        $users = array();
        foreach (file(__DIR__.'/../../../../app/config/apikeys.txt') as $line) {
            // skip commented and blank lines
            if (preg_match('/(^#|^\s*$)/', $line)) {
                continue;
            }

            list($user, $key) = explode(':', trim($line), 2);
            $users[$key] = $user;
        }

        if (isset($users[$apikey])) {
            return new User($users[$apikey], $apikey, array('ROLE_USER'));
        }

        throw new UsernameNotFoundException(sprintf('API Key "%s" does not exist.', $apikey));
    }

    /* -- SimpleHttpAuthenticatorInterface methods -- */

    public function createToken(Request $request, $providerKey)
    {
        return new PreAuthenticatedToken('anon.', $request->query->get('apikey'), $providerKey);
    }

    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        try {
            $user = $this->loadUserByApiKey($token->getCredentials());
        } catch (UsernameNotFoundException $e) {
            throw new AuthenticationException('Invalid api key');
        }

        return new PreAuthenticatedToken($user, $token->getCredentials(), $providerKey, $user->getRoles());
    }

    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof PreAuthenticatedToken && $token->getProviderKey() === $providerKey;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
    }

    /* -- UserProviderInterface methods -- */

    public function loadUserByUsername($username)
    {
        // load users from flat file user "database"
        $users = array();
        foreach (file(__DIR__.'/../../../../app/config/apikeys.txt') as $line) {
            // skip commented and blank lines
            if (preg_match('/(^#|^\s*$)/', $line)) {
                continue;
            }

            list($user, $apikey) = explode(':', trim($line), 2);
            $users[$user] = $apikey;
        }

        if (isset($users[$username])) {
            return new User($username, $users[$username], array('ROLE_USER'));
        }

        throw new UsernameNotFoundException(sprintf('Username "%s" does not exist.', $username));
    }

    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByUsername($user->getCredentials());
    }

    public function supportsClass($class)
    {
        return $class === 'Symfony\Component\Security\Core\User\User';
    }
}
