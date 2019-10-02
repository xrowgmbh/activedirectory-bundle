<?php
namespace Xrow\ActiveDirectoryBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use eZ\Publish\Core\MVC\Symfony\Security\Authentication\RepositoryAuthenticationProvider;
use eZ\Publish\API\Repository\Repository;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Xrow\ActiveDirectoryBundle\Adapter\LDAP\Client;
use Xrow\ActiveDirectoryBundle\Security\User\RemoteUserHandlerInterface;
use eZ\Publish\Core\Base\Exceptions\NotFoundException;
use Xrow\ActiveDirectoryBundle\Adapter\ActiveDirectory\User;
use eZ\Publish\Core\MVC\Symfony\Security\InteractiveLoginToken;
use eZ\Publish\Core\MVC\Symfony\Security\UserWrapped;
use eZ\Publish\Core\Repository\Values\User\UserReference;
use Symfony\Component\Translation\TranslatorInterface;
use Xrow\ActiveDirectoryBundle\RemoteIDGenerator;

class ActiveDirectoryProvider extends RepositoryAuthenticationProvider implements AuthenticationProviderInterface
{
    /*** @var UserProviderInterface */
    private $userProvider;

    /*** @var RemoteUserHandlerInterface */
    private $userHandler;

    /*** @var Client */
    private $client;

    /*** @var Repository */
    private $repository;

    /*** @var TranslatorInterface */
    private $translator;

    public function setRepository(Repository $repository)
    {
        $this->repository = $repository;
    }

    public function setUserHandler(RemoteUserHandlerInterface $userHandler)
    {
        $this->userHandler = $userHandler;
    }

    public function setClient(Client $client)
    {
        $this->client = $client;
    }

    public function setTranslator(TranslatorInterface $translator)
    {
        $this->translator = $translator;
    }

    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    /**
     *
     * @param UsernamePasswordToken $token            
     * @return mixed|UserInterface
     */
    protected function tryActiveDirectoryImport(UsernamePasswordToken $token)
    {
        $currentUser = $token->getUser();
        
        if ('' === ($presentedUsername = $token->getUsername())) {
            throw new AuthenticationCredentialsNotFoundException(
                /** @Desc("The presented username cannot be empty") */
                $this->translator->trans('username.empty', [], 'xrow_active_directory')
            );
        }
        
        if ('' === ($presentedPassword = $token->getCredentials())) {
            throw new AuthenticationCredentialsNotFoundException(
                /** @Desc("The presented password cannot be empty") */
                $this->translator->trans('password.empty', [], 'xrow_active_directory')
            );
        }
        
        // communication errors and config errors should be logged/handled by the client
        try {
            $user = $this->client->authenticateUser($presentedUsername, $presentedPassword);
        } catch (\Exception $e) {
            throw new BadCredentialsException(
                /** @Desc("The presented username or password is invalid") */
                $this->translator->trans('client.failure', [], 'xrow_active_directory')
            );
        }

        try {
            $apiUser = $this->repository->getUserService()->loadUserByLogin( $user->getUserPrincipalName() );
        } catch (\Exception $e) {
            $RepoUser = $this->userHandler->createRepoUser($user);
            return new UserWrapped(new User($user,  $user->getUserPrincipalName(), $presentedPassword), $RepoUser);
        }

        $RepoUser = $this->userHandler->updateRepoUser($user, $apiUser);
        return new UserWrapped(new User($user,  $user->getUserPrincipalName(), $presentedPassword), $RepoUser);
    }

    /**
     * Copied from UserAuthenticationProvider
     */
    protected function getRoles(UserInterface $user, TokenInterface $token)
    {
        $roles = $user->getRoles();
        
        foreach ($token->getRoles() as $role) {
            if ($role instanceof SwitchUserRole) {
                $roles[] = $role;
                
                break;
            }
        }
        
        return $roles;
    }

    private function isValidActiveDirectoryUser($apiUser)
    {
        return RemoteIDGenerator::validate( $apiUser->getVersionInfo()->getContentInfo()->remoteId );
    }

    public function authenticate(TokenInterface $token)
    {
        if ($token instanceof InteractiveLoginToken) {
            return $token;
        }
        // $currentUser can either be an instance of UserInterface or just the username (e.g. during form login).
        /** @var EzUserInterface|string $currentUser */
        $currentUser = $token->getUser();
        if ($currentUser instanceof UserInterface) {
            return $currentUser;
        }
        
        try {
            $UserNative = $this->repository->getUserService()->loadUserByLogin($token->getUsername());
        } catch (NotFoundException $e) {
            $UserNative = false;
        }

        try {
            $ADUser = $this->repository->getUserService()->loadUserByLogin($this->client->getAccountName($token->getUsername()));
        } catch (NotFoundException $e) {
            $ADUser = false;
        } catch (\Exception $e) {
            $ADUser = false;
        }

        $apiUser = false;
        if ($ADUser and $this->isValidActiveDirectoryUser($ADUser)) {
            try {
                $UserWrapped = $this->tryActiveDirectoryImport($token);
                $token->setAttribute("username",  $this->client->getAccountName($token->getUsername()));
            } catch (\Exception $e) {
                throw new BadCredentialsException(
                    /** @Desc("Invalid directory user") */
                    $this->translator->trans('user.invalid', [], 'xrow_active_directory'), 0, $e
                );
            }
        } else {
            try {
                $UserWrapped = $this->tryActiveDirectoryImport($token);
                $token->setAttribute("username", $this->client->getAccountName($token->getUsername()));
            } catch (\Exception $e) {
                if (! $UserNative) {
                    throw new BadCredentialsException(
                        /** @Desc("Invalid directory user") */
                        $this->translator->trans('user.invalid', [], 'xrow_active_directory'), 0, $e
                    );
                }
                // go on with native users
            }
        }

        // Try normal login
        if (! $apiUser and $UserNative) {
            try {
                $apiUser = $this->repository->getUserService()->loadUserByCredentials($token->getUsername(), $token->getCredentials());
                // $UserWrapped = new UserWrapped( new \eZ\Publish\Core\MVC\Symfony\Security\User( $apiUser ), $apiUser);
                $UserWrapped = new \eZ\Publish\Core\MVC\Symfony\Security\User($apiUser);
            } catch (\Exception $e) {
                throw new BadCredentialsException(
                    /** @Desc("Invalid credentials") */
                    $this->translator->trans('credentials.invalid', [], 'xrow_active_directory'), 0, $e
                );
            }
        }

        // Can`t find the user anywhere
        if (! $UserWrapped) {
            throw new UsernameNotFoundException(
                /** @Desc("Invalid directory user") */
                $this->translator->trans('user.invalid', [], 'xrow_active_directory'), 0, $e
            );
        }
        
        if ($currentUser instanceof UserInterface) {
            if ($currentUser->getAPIUser()->passwordHash !== $user->getAPIUser()->passwordHash) {
                throw new BadCredentialsException(
                    /** @Desc("The credentials were changed from another session") */
                    $this->translator->trans('credentials.changed', [], 'xrow_active_directory'), 0, $e
                );
            }
            $apiUser = $currentUser->getAPIUser();
        }
        
        // Finally inject current user
        $permissionResolver = $this->repository->getPermissionResolver();
        $UserReference = new UserReference($UserWrapped->getAPIUser()->id);
        $permissionResolver->setCurrentUserReference($UserReference);
        $providerKey = method_exists($token, 'getProviderKey') ? $token->getProviderKey() : __CLASS__;
        $interactiveToken = new InteractiveLoginToken($UserWrapped, get_class($token), $token->getCredentials(), $providerKey, $token->getRoles());
        $interactiveToken->setAttributes($token->getAttributes());
        
        return $interactiveToken;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken;
    }
}