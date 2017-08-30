<?php

namespace Xrow\ActiveDirectoryBundle\Security\User;

use Adldap\Models\User as ActiveDirectoryUser;

interface RemoteUserHandlerInterface
{
    /**
     * @param RemoteUser $user
     * @return \eZ\Publish\API\Repository\Values\User\User
     */
    public function createRepoUser(ActiveDirectoryUser$user);

    /**
     * @param ActiveDirectoryUser $user
     * @param $eZUser (is this an \eZ\Publish\API\Repository\Values\User\User ?)
     */
    public function updateRepoUser(ActiveDirectoryUser $user, $eZUser);

    /**
     * Returns the API user corresponding to a given remoteUser (if it exists), or false.
     *
     * @param ActiveDirectoryUser $remoteUser
     * @return \eZ\Publish\API\Repository\Values\User\User|false
     */
    public function loadAPIUserByRemoteUser( ActiveDirectoryUser $remoteUser);

    /**
     * Optional method: it will be called, if implemented, just after the remote user has logged in and the local user has
     * been created/updated
     *
     * @return null
     * public function onRemoteUserLogin(RemoteUser $user, $eZUser);
     */
}
