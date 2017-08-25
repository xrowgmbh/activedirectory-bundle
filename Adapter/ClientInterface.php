<?php

namespace Xrow\ActiveDirectoryBundle\Adapter;

#use Xrow\ActiveDirectoryBundle\Security\User\RemoteUser;

interface ClientInterface
{
    /**
     * @param string $login
     * @param string $password
     * @return RemoteUser
     * @throws BadCredentialsException|AuthenticationServiceException
     */
    public function authenticateUser($login, $password);
}