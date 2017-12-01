<?php
namespace NinjaSentry\Katana\Firewall\Detect;

use NinjaSentry\Sai\Http;
//use MaxMind\GeoIp\GeoIP;

/**
 * Class Country
 * 
 * Country IP detection with the MaxMind Geo IP database
 *
 * @package NinjaSentry\Katana\Firewall\Detect
 */
final class Country
{
    /**
     * @var string
     */
    private $path = '';
    
    /**
     * @var string
     */
    private $geo_inc = '';
    
    /**
     * @var string
     */
    private $geo_dat = '';
    
    /**
     * @var
     */
    private $gi;
    
    /**
     * @param array $options
     * @throws \Exception
     */
    public function __construct( $options = [] )
    {
        $this->path    = $options['path'];
        $this->geo_inc = $this->path . 'geoip.inc';
        $this->geo_dat = $this->path . 'geoip.dat';
        
        $this->getGeoInc();
        $this->getGeoDat();
    }
    
    /**
     * @param string $ip
     * @return bool
     */
    public function getCode( $ip = '' ){
        return \geoip_country_code_by_addr( $this->gi, $ip );
    }
    
    /**
     * @param string $ip
     * @return bool
     */
    public function getName( $ip = '' ){
        return \geoip_country_name_by_addr( $this->gi, $ip );
    }
    
    /**
     * Close it down directly
     */
    public function close(){
        \geoip_close( $this->gi );
    }
    
    /**
     * Load geo ip inc file or die
     * @throws \Exception
     */
    private function getGeoInc()
    {
        if( false === ( is_readable( $this->geo_inc ) ) )
        {
            throw new \Exception(
                __METHOD__ . ' Detection Error :: getGeoInc() - '
                . 'Required GeoIp.inc file not found in path ( '
                . escaped( $this->geo_inc )
                . ' )'
                , Http\Status::SERVICE_UNAVAILABLE
            );
        }
        
        include_once $this->geo_inc;
    }
    
    /**
     * Load geo ip data file or die
     * @throws \Exception
     */
    private function getGeoDat()
    {
        if( false === ( is_readable( $this->geo_dat ) ) )
        {
            throw new \Exception(
                __METHOD__ . ' Detection Error :: getGeoDat() - ' 
                . 'Required GeoIp.dat file not found in path ( '
                . escaped( $this->geo_dat )
                . ' )'
                , Http\Status::SERVICE_UNAVAILABLE
            );
        }
    
        $this->gi = \geoip_open( $this->geo_dat, GEOIP_STANDARD );
    }
}
