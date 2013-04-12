<?php

namespace Acme\DemoBundle\Security;

use Symfony\Component\Security\Core\Authentication\SimpleFormAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;

class FormAuthenticator implements SimpleFormAuthenticatorInterface, UserProviderInterface
{
    private $encoderFactory;

    public function __construct(EncoderFactoryInterface $encoderFactory)
    {
        $this->encoderFactory = $encoderFactory;
    }

    /* -- SimpleFormAuthenticatorInterface methods -- */

    public function createToken(Request $request, $username, $password, $providerKey)
    {
        return new UsernamePasswordToken($username, $password, $providerKey);
    }

    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        try {
            $user = $userProvider->loadUserByUsername($token->getUsername());
        } catch (UsernameNotFoundException $e) {
            throw new AuthenticationException('Invalid username or password');
        }

        if ($this->encoderFactory->getEncoder($user)->isPasswordValid($user->getPassword(), $token->getCredentials(), $user->getSalt())) {
            return new UsernamePasswordToken($user, 'bar', 'dummy', $user->getRoles());
        }

        throw new AuthenticationException('Invalid username or password');
    }

    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof UsernamePasswordToken && $token->getProviderKey() === $providerKey;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        // TODO this doesn't get called yet
        return new Response('FAILED TO AUTH WITH USER/PWD', 400);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
    }

    /* -- UserProviderInterface methods -- */

    public function loadUserByUsername($username)
    {
        // load users from flat file user "database"
        $users = array();
        foreach (file(__DIR__.'/../../../../app/config/users.txt') as $line) {
            // skip commented and blank lines
            if (preg_match('/(^#|^\s*$)/', $line)) {
                continue;
            }

            list($user, $pwd) = explode(':', trim($line), 2);
            $users[$user] = $pwd;
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

        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class)
    {
        return $class === 'Symfony\Component\Security\Core\User\User';
    }
}
