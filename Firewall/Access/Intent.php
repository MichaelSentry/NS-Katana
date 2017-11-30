<?php
namespace NinjaSentry\Katana\Firewall\Access;

use NinjaSentry\Sai\Http;
use NinjaSentry\Katana\Filter\Ip as IpFilter;

/**
 * Class Intent
 *
 * @package NinjaSentry\Katana\Firewall\Access
 */
final class Intent
{
    /**
     * Client profile
     * @var array
     */
    private $profile = [];

    /**
     * Validation policy 
     * @var array
     */
    private $policy = [];

    /**
     * Remote ip address
     * 
     * @var
     */
    private $ip;

    /**
     * @var
     */
    private $ua;

    /**
     * @param array $profile
     */
    public function __construct( $profile = [] )
    {
        $this->profile = $profile;

        $this->ip = $this->profile['ip_addr'];
        $this->ua = $this->profile['useragent'];

        $this->getPolicy();
    }

    /**
     * Load search engine validation policy
     */
    private function getPolicy()
    {
        if( is_readable( '../app/config/firewall/policy/search-engine-validation.php' ) ) {
            $this->policy = require '../app/config/firewall/policy/search-engine-validation.php';
        }
    }

    /**
     * Validate supported search engines
     * @param string $match
     * @return bool
     */
    public function validateSearchEngine( $match = '' )
    {
        if( empty( $this->policy ) || ! is_array( $this->policy ) ) {
            return false;
        }

        switch( mb_strtolower( $match ) )
        {
            case('googlebot'):
                return $this->validateGoogleBot();
                break;

            case('bingbot'):
            case('msnbot'):
                return $this->validateBingBot();
                break;

            case('slurp'):
            case('yahoo'):
                return $this->validateYahoo();
                break;

            case('duckduckbot'):
                return $this->validateDuck();
                break;

            default:
                // echo 'Search engine name is not supported (' . $match . ')';
                break;
        }

        return false;
    }

    /**
     * Validate Googlebot useragent matches a Google IP range
     *
     * @return bool
     * @throws \Exception
     */
    private function validateGoogleBot()
    {
        if( isset( $this->policy['google_allow'] ) ) 
        {
            if( IpFilter::inCidrList( $this->ip, $this->policy['google_allow'] ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return bool
     * @throws \Exception
     */
    private function validateBingBot()
    {
        if( isset( $this->policy['microsoft_allow'] ) )
        {
            if( IpFilter::inCidrList( $this->ip, $this->policy['microsoft_allow'] ) ) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * @return bool
     * @throws \Exception
     */
    private function validateYahoo()
    {
        if( isset( $this->policy['yahoo_allow'] ) ) 
        {
            if( IpFilter::inCidrList( $this->ip, $this->policy['yahoo_allow'] ) ) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * @return bool
     * @throws \Exception
     */
    private function validateDuck()
    {
        if( isset( $this->policy['duck_allow'] ) ) 
        {
            if( IpFilter::inCidrList( $this->ip, $this->policy['duck_allow'] ) ) {
                return true;
            }
        }

        return false;
    }
}
