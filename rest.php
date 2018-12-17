<?php
require_once('constants.php');
class Rest{
  protected $request;
  protected $serviceName;
  protected $param;
  protected $userId;

  public function __construct(){
    if($_SERVER['REQUEST_METHOD'] !== 'POST'){
      $this->throwError(REQUEST_NOT_VALID, "Método de reuisição não é válido");
    }
    $handler = fopen('php://input', 'r');
    $this->request = stream_get_contents($handler);
    $this->validateRequest($this->request);

    if ('generateToken' != strtolower($this->serviceName)) {
      $this->validateToken();
    }
  }

  public function validateRequest(){
    if($_SERVER['CONTENT_TYPE'] !== 'application/json'){
      $this->throwError(REQUEST_CONTENTTYPE_NOT_VALID, 'Não é formato json');
    }

    $data = json_decode($this->request, true);
    if (!isset($data['name']) || $data['name'] == '') {
      $this->throwError(API_NAME_REQUIRED, 'Nome da api está vazio');
    }
    $this->serviceName = $data['name'];
    $data = json_decode($this->request, true);

    if (!is_array($data)) {
      $this->throwError(API_PARAM_REQUIRED, 'Sem parametro nome');
    }
    $this->serviceName = $data['name'];
    $this->param = $data['param'];
  }

  public function validateToken() {
			try {
				$token = $this->getBearerToken();
				$payload = JWT::decode($token, SECRETE_KEY, ['HS256']);
				$stmt = $this->dbConn->prepare("SELECT * FROM users WHERE id = :userId");
				$stmt->bindParam(":userId", $payload->userId);
        echo $payload->userId;
				$stmt->execute();
				$user = $stmt->fetch(PDO::FETCH_ASSOC);
				if(!is_array($user)) {
					$this->returnResponse(INVALID_USER_PASS, "This user is not found in our database.");
				}
				if( $user['active'] == 0 ) {
					$this->returnResponse(USER_NOT_ACTIVE, "This user may be decactived. Please contact to admin.");
				}
				$this->userId = $payload->userId;
			} catch (Exception $e) {
				$this->throwError(ACCESS_TOKEN_ERRORS, $e->getMessage());
			}
		}

  public function proccessApi(){
    $api = new API;
    $rMethod = new ReflectionMethod('API', $this->serviceName);
    if(!method_exists($api, $this->serviceName)){
      $this->throwError(API_DOST_NOT_EXIST, 'Api não existe');
    }
    $rMethod->invoke($api);
  }

  public function throwError($code, $message){
    header('content-type: application/json');
    $errorMsg = json_encode(['status'=>$code, 'message'=>$message]);
    echo $errorMsg;
    exit;
  }

  public function returnResponse($code, $data){
    header('content-type: application/json');

    $response = json_encode(['response'=>['status'=>$code,'result'=>$data]]);
    echo $response; exit;
  }

  public function validateParameter($fieldName, $value, $dataType, $required = true){
    if($required == true && empty($value)){
      $this->throwError(VALIDATE_PARAMETER_REQUIRED, $fieldName. ' PARAMETER  is required');
    }

    switch ($dataType) {
      case BOOLEAN:
        if(!is_bool($value)){
          $this->throwError(VALIDATE_PARAMETER_DATATYPE, $fieldName. $dataType.'datatype is not valid');
        };
        break;
      case INTEGER:
        if(!is_numeric($value)){
          $this->throwError(VALIDATE_PARAMETER_DATATYPE, $fieldName. $dataType.'datatype is not valid');
        };
        break;
      case STRING:
        if(!is_string($value)){
          $this->throwError(VALIDATE_PARAMETER_DATATYPE, $fieldName. $dataType.'datatype is not valid');
        };
        break;
    }

    return $value;
  }

  public function getBearerToken() {
	        $headers = $this->getAuthorizationHeader();
	        // HEADER: Get the access token from the header
	        if (!empty($headers)) {
	            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
	                return $matches[1];
	            }
	        }
	        $this->throwError( ATHORIZATION_HEADER_NOT_FOUND, 'Access Token Not found');
	    }

      public function getAuthorizationHeader(){
   	        $headers = null;
   	        if (isset($_SERVER['Authorization'])) {
   	            $headers = trim($_SERVER["Authorization"]);
   	        }
   	        else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
   	            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
   	        } elseif (function_exists('apache_request_headers')) {
   	            $requestHeaders = apache_request_headers();
   	            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
   	            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
   	            if (isset($requestHeaders['Authorization'])) {
   	                $headers = trim($requestHeaders['Authorization']);
   	            }
   	        }
   	        return $headers;
   	    }


}
 ?>
