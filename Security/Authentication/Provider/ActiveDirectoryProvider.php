<?php
namespace Xrow\ActiveDirectoryBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use eZ\Publish\Core\MVC\Symfony\Security\Authentication\RepositoryAuthenticationProvider;
use eZ\Publish\API\Repository\Repository;
use Assetic\Exception\Exception;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Ldap\LdapClient;
use Xrow\ActiveDirectoryBundle\Adapter\LDAP\Client;

class ActiveDirectoryProvider extends RepositoryAuthenticationProvider implements AuthenticationProviderInterface
{
    private $userProvider;
    /**
     * @var \eZ\Publish\API\Repository\Repository
     */
    private $repository;
    
    public function setRepository(Repository $repository)
    {
        $this->repository = $repository;
    }
    
    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }
    /**
     * @param UsernamePasswordToken $token
     * @return mixed|UserInterface
     */
    protected function tryActiveDirectoryImport(UsernamePasswordToken $token)
    {
        $currentUser = $token->getUser();
        if ($currentUser instanceof UserInterface) {
            
            /// @todo check if this is a good idea or not: keeping user password in the token ? Maybe encrypt it!
            if ($currentUser->getPassword() !== $token->getCredentials()) {
                throw new BadCredentialsException('The credentials were changed from another session.');
            }
            return $currentUser;
            
        } else {
            
            /// @todo !important might want to throw AuthenticationCredentialsNotFoundException instead?
            if ('' === ($presentedUsername = $token->getUsername())) {
                throw new BadCredentialsException('The presented email cannot be empty.');
            }
            
            if ('' === ($presentedPassword = $token->getCredentials())) {
                throw new BadCredentialsException('The presented password cannot be empty.');
            }
            var_dump($presentedUsername);
            var_dump($presentedPassword);
            $client = new LdapClient("dc01.xrow.lan");
            $this->client = new Client($client, array(
                'search_dn' => 'XROW' . "\\" . $presentedUsername,
                'base_dn' => 'dc=XROW,dc=LAN',
                'search_password' => $presentedPassword
            ));
            $user = $this->client->AuthenticateUser($presentedUsername, $presentedPassword);
            
            // communication errors and config errors should be logged/handled by the client
            try {
                
                $user = $this->client->AuthenticateUser($presentedUsername, $presentedPassword);
                // the client should return a UserInterface, no need for us to use a userProvider
                //$user = $this->userProvider->loadUserByUsername($username);
                return $user;
                
            } catch(\Exception $e) {
                throw new BadCredentialsException('The presented username or password is invalid.');
            }
            
            // no need to check the password after loading the user: the remote ws does that
            /*if (!$this->encoderFactory->getEncoder($user)->isPasswordValid($user->getPassword(), $presentedPassword, $user->getSalt())) {
             throw new BadCredentialsException('The presented password is invalid.');
             }*/
        }
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
    public function authenticate( TokenInterface $token )
    {
        // $currentUser can either be an instance of UserInterface or just the username (e.g. during form login).
        /** @var EzUserInterface|string $currentUser */
        $currentUser = $token->getUser();

        try {
            $apiUser = $this->repository->getUserService()->loadUserByLogin( $token->getUsername() );
        } catch ( \Exception $e) {
            $apiUser = $this->tryActiveDirectoryImport( $token );
        }
        if (!isset($apiUser)){
            throw new UsernameNotFoundException('Invalid username', 0, $e);
        }
        #$remoteid = $apiUser->getVersionInfo()->getContentInfo()->remoteId;
        #preg_match('@^(ActiveDirectory):([^:]+):([^:]+):(.+)@i', $remoteid, $test);
        #if (isset($test[1]) and $test[1] === "ActiveDirectory" ){
        #    $this->tryActiveDirectoryImport( $token );
        #}

        if ($currentUser instanceof UserInterface) {
            if ($currentUser->getAPIUser()->passwordHash !== $user->getAPIUser()->passwordHash) {
                throw new BadCredentialsException('The credentials were changed from another session.');
            }
            $apiUser = $currentUser->getAPIUser();
        } else {
            try {
                $apiUser = $this->repository->getUserService()->loadUserByCredentials($token->getUsername(), $token->getCredentials());
            } catch (NotFoundException $e) {
                throw new BadCredentialsException('Invalid credentials', 0, $e);
            }
        }
        
        
        #var_dump($apiUser);die("here");
        // Finally inject current user 
        $permissionResolver = $this->repository->getPermissionResolver();
        $apiUser = $this->repository->getUserService()->loadUserByLogin( "admin" );
        $permissionResolver->setCurrentUserReference($apiUser);

    }
    
    public function supports(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken;
    }
}