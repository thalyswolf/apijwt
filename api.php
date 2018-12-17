<?php
class Api extends Rest {
  public $dbConn;
  public function __construct(){
    parent::__construct();
    $db = new DbConnect;
    $this->dbConn = $db->connect();
  }

  public function generateToken(){
    $email = $this->validateParameter('email', $this->param['email'], STRING);
    $pass = $this->validateParameter('pass', $this->param['pass'], STRING);
    $stmt = $this->dbConn->prepare("SELECT * FROM users WHERE email = :email
                            AND password = :pass");
    $stmt->bindParam(":email", $email);
    $stmt->bindParam(":pass", $pass);

    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if(!is_array($user)){
      $this->returnResponse(INVALID_USER_PASS, 'Email ou senha incorreta');
    }
    if($user['active'] == 0){
      $this->returnResponse(INVALID_USER_PASS, 'user inativo');
    }
    $payload = [
      'iat' => time(),
      'iss' => 'localhost',
      'exp' => time() + (15*60),
      'userId' => $user['id']
    ];
    $jwt = new JWT();
    $token = $jwt->encode($payload, SECRETE_KEY);
    $data = ['token'=>$token];
    $this->returnResponse(SUCCESS_RESPONSE, $data);
  }

  public function addCustomer(){
    $name = $this->validateParameter('name', $this->param['name'], STRING, false);
    $email = $this->validateParameter('email', $this->param['email'], STRING);
    $addr = $this->validateParameter('addr', $this->param['addr'], STRING, false);
    $mobile = $this->validateParameter('mobile', $this->param['mobile'], STRING, false);

    try {
      $token = $this->getBearerToken();
      $payload = JWT::decode($token, SECRETE_KEY, ['HS256']);
      $stmt = $this->dbConn->prepare("SELECT * FROM users WHERE id=:id");

      $stmt->bindParam(":id", $payload->userId);

      $stmt->execute();
      $user = $stmt->fetch(PDO::FETCH_ASSOC);
      if(!is_array($user)){
        $this->returnResponse(INVALID_USER_PASS, 'Not found');
      }
      if($user['active'] == 0){
        $this->returnResponse(INVALID_USER_PASS, 'user inativo');
      }
      $cust = new Customer;
      $cust->setName($name);
      $cust->setEmail($email);
      $cust->setAddress($addr);
      $cust->setMobile($mobile);
      $cust->setCreatedBy($payload->userId);
      $cust->setCreatedOn(date('Y-m-d'));
      $booStatus = true;
      if (!$cust->insert()) {
        $errMsg = 'Failed to insert';
        $booStatus = false;
      } else{
        $message = "Inserted successfuly";
      }

      $this->returnResponse(SUCCESS_RESPONSE, $message);

    } catch (\Exception $e) {
      $this->throwError(ACCESS_TOKEN_ERRORS, $e->getMessage());
    }

  }

  public function getCustomerDetails(){
    $customerId = $this->validateParameter('customerId', $this->param['customerId'], INTEGER);
    $cust = new Customer;
    $cust->setId($customerId);
    $customer = $cust->getCustomerDetailsById();
    if (!is_array($customer)) {
      $this->returnResponse(SUCCESS_RESPONSE, 'Customer detais are not in DB');
    }

    $response['customerId'] = $cust['id'];
    $response['customerName'] = $cust['name'];
    $response['email'] = $cust['email'];
    $response['mobile'] = $cust['mobile'];
    $response['address'] = $cust['address'];
    $response['created_by'] = $cust['created_user'];
    $response['last_updated_by'] = $cust['updated_user'];
    $this->returnResponse(SUCCESS_RESPONSE, $response);

  }
}

 ?>
