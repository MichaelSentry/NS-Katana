<?php
namespace NinjaSentry\Katana\Form;

/**
 * NinjaSentry Form Guard
 * ----------------------
 * ninjasentry.com - 2017
 */

use NinjaSentry\Sai\Http;
use NinjaSentry\Sai\Authentication;

/**
 * Class Guard
 *
 * @package NinjaSentry\Katana\Form
 */
final class Guard
{
    /**
     * Form token hash algorithm
     */
    const HASH_ALGO = 'sha256';
    
    /**
     * CSRF guard key
     */
    const CSRF_TOKEN = 'csrf_token';
    
    /**
     * Form token key
     */
    const FORM_TOKEN = 'form_token';
    
    /**
     * Form fields key
     */
    const FORM_FIELDS = 'form_fields';
    
    /**
     * Form action token key
     */
    const ACTION_TOKEN = 'action_token';
    
    /**
     * @var \NinjaSentry\Sai\Authentication
     */
    public $identity;
    
    /**
     * Form field map
     * @var array
     */
    private $fields = [];
    
    /**
     * @param \NinjaSentry\Sai\Authentication $identity
     */
    public function __construct( Authentication $identity ){
        $this->identity = $identity;
        $this->appToken = $identity->getAppToken();
    }
    
    /**
     * Generate a form action url token
     *
     * @param string $key
     * @return string
     * @throws \Exception
     */
    public function actionToken( $key = Guard::ACTION_TOKEN )
    {
        if( ! is_string( $key ) )
        {
            throw new \Exception(
                'Form Guard Error :: actionToken( $key ) - $key must be a string value. '
                . 'Current type ( '
                . gettype( $key )
                . ' )'
                , Http\Status::SERVICE_UNAVAILABLE
            );
        }
        
        return \hash_hmac( self::HASH_ALGO, $key, $this->appToken );
    }
    
    /**
     * Lock form fields with a HMAC hash
     *
     * @param array $fields
     * @return array
     * @throws \Exception
     */
    public function lockFields( $fields = [] )
    {
        if( ! is_array( $fields ) )
        {
            throw new \Exception(
                'FormGuard Error :: lockFields() - '
                . 'Fields input must be an array. Current type ( '
                . gettype( $fields )
                . ' )'
                , Http\Status::SERVICE_UNAVAILABLE
            );
        }
        
        $hashed = [];
        
        foreach( $fields as $fieldName )
        {
            if( isset( $hashed[ $fieldName ] ) )
            {
                throw new \Exception(
                    'FormGuard Error :: lockFields() - Duplicate field name detected. '
                    . 'A hashed form field with this name already exists ( '
                    . escaped( $fieldName )
                    . ' )'
                    , Http\Status::SERVICE_UNAVAILABLE
                );
            }
            
            $hashed[ $fieldName ] = \base64_encode(
                \hash_hmac( Guard::HASH_ALGO, $fieldName, $this->appToken )
            );
        }
        
        return $hashed;
    }
    
    /**
     * Enforce form guard protections
     *
     * @param \NinjaSentry\Sai\Http\Route $route
     * @throws \Exception
     */
    public function enforce( Http\Route $route )
    {
        $this->validateActionToken( $route );
        $this->getFields();
        $this->fieldsMatch();
        $this->rewritePost();
        $this->validateFormToken();
    }
    
    /**
     * Get form fields from session data
     *
     * @throws \Exception
     */
    private function getFields()
    {
        if( ! $this->identity->has( Guard::FORM_FIELDS ) )
        {
            throw new \Exception(
                'Form Guard Error :: rewritePost() - '
                . 'Required session key ( '
                . Guard::FORM_FIELDS
                . ' ) was not found'
                , Http\Status::SERVICE_UNAVAILABLE
            );
        }
        
        $this->fields = $this->identity->get( Guard::FORM_FIELDS );
    }
    
    /**
     * Form action url token validation
     * @param \NinjaSentry\Sai\Http\Route $route
     * @throws \Exception
     */
    private function validateActionToken( Http\Route $route )
    {
        $requestToken = $route->param;
        
        if( empty( $requestToken ) )
        {
            throw new \Exception(
                'FormGuard Error :: validateActionToken() - '
                . 'Required form action token was not found in route'
                , Http\Status::BAD_REQUEST
            );
        }
        
        $sessionToken = $this->identity->has( Guard::ACTION_TOKEN )
            ? $this->identity->get( Guard::ACTION_TOKEN )
            : '';
        
        if( empty( $sessionToken ) )
        {
            throw new \Exception(
                'FormGuard Error :: validateActionToken() - '
                . 'Required form action token was not found in session'
                , Http\Status::SERVICE_UNAVAILABLE
            );
        }
        
        if( false === ( hash_equals( $sessionToken, $requestToken ) ) )
        {
            throw new \Exception(
                'FormGuard Error :: validateActionToken() - '
                . 'Form action token failed validation [ no match found ]'
                , Http\Status::BAD_REQUEST
            );
        }
    }
    
    /**
     * Detect form tampering
     *
     * @throws \Exception
     */
    private function fieldsMatch()
    {
        $fieldCounter = count( $this->fields, true );
        $postCounter  = count( $_POST, true );
        
        if( $fieldCounter !== $postCounter )
        {
            throw new \Exception(
                'Form Guard Error :: fieldsMatch() - Form field validation warning'
                . ' - Potential form tampering detected ( POST field count : '
                . $postCounter
                . ' does not match original field count : '
                . $fieldCounter
                . ' )'
                , Http\Status::BAD_REQUEST
            );
        }
    }
    
    /**
     * Rebuild POST array
     * De-obfuscate form field key/values
     *
     * @throws \Exception
     */
    private function rewritePost()
    {
        foreach( $this->fields as $key => $value )
        {
            if( empty( $key ) ) continue;
            if( empty( $value ) ) continue;
            
            if( ! array_key_exists( $value, $_POST ) )
            {
                throw new \Exception(
                    'Form Guard :: Expected form field value not found in post data ( '
                    . $value
                    . ' )'
                    , Http\Status::SERVICE_UNAVAILABLE
                );
            }
            
            $_POST[ $key ] = $_POST[ $value ];
            unset( $_POST[ $value ] );
        }
    }
    
    /**
     * CSRF form token validation
     * Removed from post data once validated
     *
     * @throws \Exception
     */
    private function validateFormToken()
    {
        if( ! isset( $_POST[ Guard::CSRF_TOKEN ] ) )
        {
            throw new \Exception(
                'Form Guard Error :: validateFormToken() - '
                . 'CSRF token not found in POST data'
                , Http\Status::BAD_REQUEST
            );
        }
        
        if( ! $this->identity->has( Guard::FORM_TOKEN ) )
        {
            throw new \Exception(
                'Form Guard Error :: validateFormToken() - '
                . 'Form token not found in session'
                , Http\Status::SERVICE_UNAVAILABLE
            );
        }
        
        $csrfToken = $_POST[ Guard::CSRF_TOKEN ];
        $formToken = $this->identity->get( self::FORM_TOKEN );
        
        if( false === ( hash_equals( $formToken, $csrfToken ) ) )
        {
            throw new \Exception(
                'Form Guard Error :: validateFormToken() - '
                . 'Form token does not match original CSRF token in session'
                , Http\Status::BAD_REQUEST
            );
        }
        
        unset( $_POST[ Guard::CSRF_TOKEN ] );
    }
}
