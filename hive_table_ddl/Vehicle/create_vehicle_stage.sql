CREATE TABLE staging.w_vehicle_d_stg(
  vehicle_key decimal(10,0),
  integration_id varchar(100),
  vin_prefix varchar(100),
  vin varchar(100),
  model_key decimal(10,0),
  production_dt varchar(50),
  sale_dt varchar(50),
  warr_start_dt varchar(50),
  msrp_amt decimal(22,7),
  dlr_inv_amt decimal(22,7),
  odomtr_rdg decimal(22,7),
  demo_flg char(1),
  demo_dt varchar(50),
  disposer_flg char(1),
  delivery_dt varchar(50),
  created_on_dt varchar(50),
  changed_on_dt varchar(50),
  delete_flg char(1),
  insert_dt varchar(50),
  update_dt varchar(50),
  srvc_cntrct_type varchar(50),
  prod_month_year varchar(10),
  prod_year decimal(6,0),
  prod_month decimal(2,0),
  foreign_veh_ind char(1),
  engine_nbr varchar(50),
  transm_nbr varchar(50),
  subaru_ind char(1),
  tm_enable_flg char(1),
  lemon_law_flg char(1),
  polk_info_flg char(1)
 )
ROW FORMAT DELIMITED FIELDS TERMINATED BY ","
TBLPROPERTIES ('skip.header.line.count' = '1');




LOAD data INPATH '/raw/edw/w_vehicle_d_stg/' INTO TABLE staging.w_vehicle_d_stg