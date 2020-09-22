<?php 
  class DB {   
    private $conn;
    public function __construct(){
        $this->conn = new mysqli(DB_HOST, DB_USER, DB_PASSWORD,DB_NAME);
        if ($this->conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }
        return $this->conn;
    }

     /*
     * Returns rows from the database based on the conditions
     * @param string name of the table
     * @param array select, where, order_by, limit and return_type conditions
     */
    public function getRows($table, $conditions = array()){
      $sql = 'SELECT ';
      $sql .= array_key_exists("select", $conditions)?$conditions['select']:'*';
      $sql .= ' FROM '.$table;
      if(array_key_exists("where", $conditions)){
          $sql .= ' WHERE ';
          $i = 0;

          $conditions['where'] = $this->escapeAll($conditions['where']);

          foreach($conditions['where'] as $key => $value){
              $pre = ($i > 0)?' AND ':'';
              $sql .= $pre.$key." = '".$value."'";
              $i++;
          }
      }
      
      if(array_key_exists("like", $conditions) && !empty($conditions['like'])){
          $sql .= (strpos($sql, 'WHERE') !== false)?' AND ':' WHERE ';
          $i = 0;
          $likeSQL = '';

          $conditions['like'] = $this->escapeAll($conditions['like']);
          foreach($conditions['like'] as $key => $value){
              $pre = ($i > 0)?' AND ':'';
              $likeSQL .= $pre.$key." LIKE '%".$value."%'";
              $i++;
          }
          $sql .= '('.$likeSQL.')';
      }
      
      if(array_key_exists("like_or", $conditions) && !empty($conditions['like_or'])){
          $sql .= (strpos($sql, 'WHERE') !== false)?' AND ':' WHERE ';
          $i = 0;
          $likeSQL = '';
          $conditions['like_or'] = $this->escapeAll($conditions['like_or']);
          foreach($conditions['like_or'] as $key => $value){
              $pre = ($i > 0)?' OR ':'';
              $likeSQL .= $pre.$key." LIKE '%".$value."%'";
              $i++;
          }
          $sql .= '('.$likeSQL.')';
      }
      
      if(array_key_exists("order_by", $conditions)){
          $sql .= ' ORDER BY '.$conditions['order_by']; 
      }
      
      if(array_key_exists("start", $conditions) && array_key_exists("limit", $conditions)){
          $sql .= ' LIMIT '.$conditions['start'].','.$conditions['limit']; 
      }elseif(!array_key_exists("start", $conditions) && array_key_exists("limit", $conditions)){
          $sql .= ' LIMIT '.$conditions['limit']; 
      }

      //echo $sql;
      $result = $this->conn->query($sql);
      
      if(array_key_exists("return_type", $conditions) && $conditions['return_type'] != 'all'){
          switch($conditions['return_type']){
              case 'count':
                  $data = $result->num_rows;
                  break;
              case 'single':
                  $data = $result->fetch_assoc();
                  break;
              default:
                  $data = '';
          }
      }else{
          if($result->num_rows > 0){
              while($row = $result->fetch_assoc()){
                  $data[] = $row;
              }
          }
      }
      return !empty($data)?$data:false;
    }
  
    /*
    * Insert data into the database
    * @param string name of the table
    * @param array the data for inserting into the table
    */
    public function insert($table, $data){
        if(!empty($data) && is_array($data)){
            $columns = '';
            $values  = '';
            $i = 0;
            if(!array_key_exists('created', $data)){
                $data['created'] = date("Y-m-d H:i:s");
            }
            if(!array_key_exists('modified', $data)){
                $data['modified'] = date("Y-m-d H:i:s");
            }

            $data = $this->escapeAll($data);

            foreach($data as $key=>$val){
                $pre = ($i > 0)?', ':'';
                $columns .= $pre.$key;
                $values  .= $pre."'".$val."'";
                $i++;
            }
            $query = "INSERT INTO ".$table." (".$columns.") VALUES (".$values.")";
            $insert = $this->conn->query($query);
            return $insert?$this->conn->insert_id:false;
        }else{
            return false;
        }
    }
  
    /*
    * Update data into the database
    * @param string name of the table
    * @param array the data for updating into the table
    * @param array where condition on updating data
    */
    public function update($table, $data, $conditions){
        if(!empty($data) && is_array($data)){
            $colvalSet = '';
            $whereSql = '';
            $i = 0;
            if(!array_key_exists('modified',$data)){
                $data['modified'] = date("Y-m-d H:i:s");
            }

            $data = $this->escapeAll($data);
            foreach($data as $key=>$val){
                $pre = ($i > 0)?', ':'';
                $colvalSet .= $pre.$key."='".$val."'";
                $i++;
            }
            if(!empty($conditions)&& is_array($conditions)){
                $whereSql .= ' WHERE ';
                $i = 0;

                $conditions = $this->escapeAll($conditions);
                foreach($conditions as $key => $value){
                    $pre = ($i > 0)?' AND ':'';
                    $whereSql .= $pre.$key." = '".$value."'";
                    $i++;
                }
            }
            $query = "UPDATE ".$table." SET ".$colvalSet.$whereSql;
            $update = $this->conn->query($query);
            return $update?$this->conn->affected_rows:false;
        }else{
            return false;
        }
    }
  
    /*
    * Delete data from the database
    * @param string name of the table
    * @param array where condition on deleting data
    */
    public function delete($table, $conditions){
        $whereSql = '';
        if(!empty($conditions) && is_array($conditions)){
            $whereSql .= ' WHERE ';
            $i = 0;
            $conditions = $this->escapeAll($conditions);
            foreach($conditions as $key => $value){
                $pre = ($i > 0)?' AND ':'';
                $whereSql .= $pre.$key." = '".$value."'";
                $i++;
            }
        }
        $query = "DELETE FROM ".$table.$whereSql;
        $delete = $this->conn->query($query);
        return $delete?true:false;
    }


    public function escape($d){
       return  $this->conn->real_escape_string($d);
    }

    public function escapeAll($data){
        foreach($data as $key=>$val){
           $data[$key] = $this->escape($data[$key]);
        }
        return $data;
    }

   

  }