<?php
namespace Xrow\ActiveDirectoryBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use eZ\Publish\Core\MVC\Symfony\Security\Authentication\RepositoryAuthenticationProvider;
use eZ\Publish\API\Repository\Repository;

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

    public function authenticate( TokenInterface $token )
    {
        var_dump($token);
        // $currentUser can either be an instance of UserInterface or just the username (e.g. during form login).
        /** @var EzUserInterface|string $currentUser */
        $currentUser = $token->getUser();

        try {
            $apiUser = $this->repository->getUserService()->loadUserByLogin( $token->getUsername() );
        } catch (NotFoundException $e) {
            throw new BadCredentialsException('Invalid credentials 2', 0, $e);
        }
        $remoteid = $apiUser->getVersionInfo()->getContentInfo()->remoteId;
        preg_match('@^(?:http://)?([^/]+)@i', $remoteid, $test);
        $schluesselwoerter = preg_split("/[\s,]+/", "hypertext language, programming");
        
        var_dump();
        #var_dump($this->repository);
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
        
        // Finally inject current user in the Repository
        $this->repository->setCurrentUser($apiUser);
        die("herehrhehhrehrhehr22");
    }
    
    public function supports(TokenInterface $token)
    {
        return $token instanceof TokenInterface;
    }
}