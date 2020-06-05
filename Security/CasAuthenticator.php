<?php

namespace L3\Bundle\CasBundle\Security;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class CasAuthenticator extends AbstractGuardAuthenticator
{
    protected $config;

    public function __construct(array $config)
    {
        $this->config = $config;

        \phpCAS::setDebug(false);

        \phpCAS::client(CAS_VERSION_2_0, $this->getParameter('host'), $this->getParameter('port'), is_null($this->getParameter('path')) ? '' : $this->getParameter('path'), true);

        if(is_bool($this->getParameter('ca')) && $this->getParameter('ca') == false) {
            \phpCAS::setNoCasServerValidation();
        } else {
            \phpCAS::setCasServerCACert($this->getParameter('ca'));
        }
    }

    public function supports(Request $request): ?bool
    {
        if($this->getParameter('gateway')) {
            $authenticated = \phpCAS::checkAuthentication();
        } else {
            $authenticated = \phpCAS::isAuthenticated();
        }
        return $authenticated;
    }

    public function getCredentials(Request $request)
    {
        return [
            'cas_user' => \phpCAS::getUser(),
            'cas_attributes' => \phpCAS::getAttributes(),
        ];
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if (null === $credentials) {
            // The token header was empty, authentication fails with HTTP Status
            // Code 401 "Unauthorized"
            return null;
        }

        $username = $credentials['cas_user'];
        $_SESSION['cas_user'] = $credentials['cas_user'];
        $_SESSION['cas_attributes'] = $credentials['cas_attributes'];

        $user = $userProvider->loadUserByUsername($username);
        if (!$user instanceof UserInterface) {
            throw new AuthenticationServiceException('The user provider must return a UserInterface object.');
        }
        return $user;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // on success, let the request continue
        return null;
    }

    /**
     * Called when authentication is needed, but it's not sent
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        if($this->getParameter('force')) {
            \phpCAS::forceAuthentication();
        }
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if($this->getParameter('force')) {
            \phpCAS::forceAuthentication();
        } else {
            return null;
        }
    }

    public function getParameter($key) {
        if(!array_key_exists($key, $this->config)) {
            throw new InvalidConfigurationException('l3_cas.' . $key . ' is not defined');
        }
        return $this->config[$key];
    }

    public function supportsRememberMe()
    {
        return false;
    }
}