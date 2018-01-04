create table if not exists users (
  id integer primary key autoincrement,
  username text UNIQUE not null,
  email text not null,
  age integer not null,
  password text not null
);