CREATE TABLE userpref (
  username varchar(100) NOT NULL,
  preference varchar(30) NOT NULL,
  value varchar(100) NOT NULL,
  prefid SERIAL PRIMARY KEY
);
CREATE INDEX username_index ON userpref(username);

