<?php
class category_mdl extends DB{

    public function __construct(){
      parent::__construct();
    }

    public function create(){

    }

    public function single($id){
       $result = $this->getRows('categories',['where'=>['id'=>$id],'return_type'=>'single']);
       return $result;
    }

    public function allcategory($data){
       //we can also write our custom sql query here
       // $this->conn->query($sql);
    }
}


?>