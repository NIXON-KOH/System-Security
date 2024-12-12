
CREATE TABLE IF NOT EXISTS room(
	id int not null auto_increment,
    name varchar(255) not null, 
    availability boolean not null,
    max_occupany integer not null,
    smoking boolean not null,
    price integer not null,
    Description varchar(255) not null,
	primary key(id)
);

CREATE TABLE IF NOT EXISTS USER(
	id int auto_increment NOT NULL,
	name varchar(255) NOT NULL,
	password varchar(255) NOT NULL,
	email varchar(255) NOT NULL,
	power int NOT NULL,
	IMGPATH varchar(255) NOT NULL,
	TOTPSECRET varchar(255) NOT NULL,
    Acc_lock boolean NOT NULL,
    First_login boolean NOT NULL,
    PRIMARY KEY(id)
);

CREATE TABLE IF NOT EXISTS logs(
	id int not null auto_increment,
    date date not null,
    user int not null,
    msg varchar(255) not null,
	primary key(id),
    foreign key (user) references user(id)
    );
insert into user values (1,'admin','$2b$12$GqLJLjOQWJleQHYdUar3rOo8OprLf/c./sAoLMyayIk87oMfzhoOW','mesphistopheles4@gmail.com',0,'https://lh3.googleusercontent.com/a/ACg8ocIN1w2RbwIOntfgGZXaRDxyUxjldR0SmYMiaScMFPlf8dPY9HA=s96','EXN4ZJ6GD3I3SDI6WYR56FGQDJP25LGL',0,1);
insert into room values (1, 'royal', 1, 10, 1, 10, 'Royal suit for the most luxurious');
insert into room values (2, 'Budget', 1, 5, 1, 20, 'Best experience for the budget friendly');
insert into room values (3, 'DayUse', 1, 5, 1, 20, 'For your daily use');
