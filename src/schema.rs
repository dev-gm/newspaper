use sqlx::{
    SqlitePool,
    query,
};
use chrono::{
    DateTime,
    FixedOffset,
    TimeZone,
};
use juniper::{
    GraphQLObject,
    GraphQLInputObject,
    RootNode,
    EmptySubscription,
    FieldResult,
    FieldError,
    graphql_value,
};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash,
        PasswordHasher,
        PasswordVerifier,
        SaltString,
    },
    Argon2,
};
use std::collections::HashMap;


pub struct Context<'a> {
    pool: SqlitePool,
    argon2: Argon2<'a>,
    users: HashMap<String, (User<'a>, String)>,
    roles: HashMap<String, Role>,
    published_posts: HashMap<i32, Post<'a>>,
    archived_posts: HashMap<i32, Post<'a>>,
}

impl Context<'_> {
    pub async fn new() -> Result<Self, String> {
        let mut context = Context::<'static> {
            pool: SqlitePool::connect(std::env::var("DATABASE_URL").or(Err(String::from("DATABASE_URL doesn't exist")))?.as_str())
                .await
                .or(Err(String::from("Couldn't connect to sqlite server at DATABASE_URL")))?,
            argon2: Argon2::default(),
            users: HashMap::new(),
            roles: HashMap::new(),
            published_posts: HashMap::new(),
            archived_posts: HashMap::new(),
        };
        User::from_db(&mut context).await?;
        Role::from_db(&mut context).await?;
        Post::from_db(&mut context).await?;
        Ok(context)
    }
}

impl juniper::Context for Context<'_> {}

/*#[async_trait]
trait FromDB {
    type Context;

    async fn from_db(context: &mut Self::Context) -> Result<(), String>;
}*/

#[derive(GraphQLObject)]
struct User<'a> {
    name: String,
    created: DateTime<FixedOffset>,
    role: &'a Role,
}

impl<'a> User<'a> {
    fn new(name: String, created: DateTime<FixedOffset>, role: &'a Role) -> Self {
        Self { name, created, role }
    }
    
    fn generate_auth(argon2: &Argon2, password: &[u8]) -> Result<String, String> {
        Ok(argon2
            .hash_password(password, &SaltString::generate(&mut OsRng))
            .or(Err(String::from("Couldn't hash password")))?
            .to_string()
        )
    }

    fn authorize(argon2: &Argon2, password_hash: String, user_input: &[u8]) -> bool {
        if let Ok(parsed_hash) = PasswordHash::new(password_hash.as_str()) {
            argon2.verify_password(user_input, &parsed_hash).is_ok()
        } else {
            false
        }
    }
}

impl<'a> User<'a> {
    async fn from_db(context: &mut Context<'a>) -> Result<(), String> {
        let users = query!("SELECT * FROM users")
            .fetch_all(&context.pool)
            .await
            .or(Err(String::from("Couldn't fetch users from database")))?;
        for user in users {
            context.users.insert(user.name, (
                Self::new(
                    user.name,
                    FixedOffset::east(0).datetime_from_str(user.created.as_str(), "%+")
                        .or(Err(format!("'created' field for user '{}' isn't formatted properly", user.name)))?,
                    context.roles.get(user.role.as_str())
                        .ok_or(format!("'role' attribute '{}' for user '{}' doesn't exist", user.role, user.name))?,
                ),
                user.password_hash,
            )).ok_or(format!("Couldn't get user '{}' from database", user.name))?;
        }
        Ok(())
    }
}

#[derive(GraphQLInputObject)]
struct NewUser {
    name: String,
    role: String,
    password: String,
}

#[derive(GraphQLObject)]
struct Role {
    post: bool,
    correct: bool,
    archive: bool,
    delete: bool,
    admin: bool,
}

impl Role {
    fn new(post: bool, correct: bool, archive: bool, delete: bool, admin: bool) -> Self {
        Self { post, correct, archive, delete, admin }
    }
}

impl Role {
    async fn from_db<'a>(context: &mut Context<'a>) -> Result<(), String> {
        let roles = query!("SELECT * FROM roles")
            .fetch_all(&context.pool)
            .await
            .or(Err(String::from("Couldn't fetch roles from database")))?;
        for role in roles {
            context.roles.insert(
                role.name.to_string(),
                Self::new(
                    role.post,
                    role.correct,
                    role.archive,
                    role.delete,
                    role.admin,
                ),
            ).ok_or(format!("Couldn't add '{}' user role profile", role.name))?;
        }
        Ok(())
    }
}

#[derive(GraphQLObject)]
struct Post<'a> {
    published: DateTime<FixedOffset>,
    title: String,
    subtitle: Option<String>,
    author: &'a User<'a>,
    content: String,
    corrections: Vec<String>,
    category: String,
    archived: bool,
}

impl<'a> Post<'a> {
    fn new(
        published: DateTime<FixedOffset>,
        title: String,
        subtitle: Option<String>,
        author: &'a User<'a>,
        content: String,
        corrections: Vec<String>,
        category: String,
        archived: bool,
    ) -> Self {
        Self { published, title, subtitle, author, content, corrections, category, archived }
    }
}

impl<'a> Post<'a> {
    async fn from_db(context: &'static mut Context<'a>) -> Result<(), String> {
        let posts = query!("SELECT * FROM posts")
            .fetch_all(&context.pool)
            .await
            .or(Err(String::from("Couldn't fetch posts from database")))?;
        for post in posts {
            match post.archived {
                false => &mut context.published_posts,
                true => &mut context.archived_posts,
            }.insert(post.id as i32, Self::new(
                FixedOffset::east(0).datetime_from_str(&post.published, "%+")
                    .or(Err(format!("Couldn't get 'published' for post '{}'", post.title)))?,
                post.title,
                post.subtitle,
                &context.users.get(post.author.as_str())
                    .ok_or(format!("author '{}' for post '{}' is an invalid user", post.author, post.title))?.0,
                post.content,
                serde_json::from_str::<Vec<String>>(post.corrections
                    .ok_or(format!("Couldn't get 'corrections' for post '{}'", post.title))?.as_str()
                ).or(Err(format!("'corrections' json object for post '{}' is invalid", post.title)))?,
                post.category,
                post.archived,
            )).ok_or(format!("Couldn't get post '{}' from database", post.title))?;
        }
        Ok(())
    }
}

#[derive(GraphQLInputObject)]
struct NewPost {
    title: String,
    subtitle: Option<String>,
    content: String, // markdown
    category: String,
}

#[derive(GraphQLInputObject)]
struct PostSearchOptions {
    limit: Option<i32>,
    before: Option<DateTime<FixedOffset>>, // before this datetime
    after: Option<DateTime<FixedOffset>>, // after this datetime
    search: Option<String>, // title or subtitle or content contains this
}

impl PostSearchOptions {
    fn with_context(&self, context: &Context, archived: bool) -> Vec<&Post> {
        let posts = match archived {
            true => context.archived_posts,
            false => context.published_posts,
        };
        posts
            .values()
            .filter(|post| {
                if let Some(before) = self.before {
                    if post.published.timestamp() > before.timestamp() {
                        return false;
                    }
                }
                if let Some(after) = self.after {
                    if post.published.timestamp() < after.timestamp() {
                        return false;
                    }
                }
                if let Some(search) = self.search {
                    search = search.to_lowercase();
                    if !post.title.to_lowercase().contains(&search) &&
                        if let Some(subtitle) = post.subtitle {
                            subtitle.to_lowercase().contains(&search)
                        } else {
                            true
                        } &&
                        !post.content.to_lowercase().contains(&search) {
                        return false
                    }
                }
                true
            })
            .collect::<Vec<&Post>>()[..
                if let Some(limit) = self.limit {
                    if limit <= posts.len() as i32 {
                        limit as usize
                    } else {
                        posts.len()
                    }
                } else {
                    posts.len()
                }]
            .to_vec()
    }
}

#[derive(GraphQLInputObject)]
struct Auth {
    username: String,
    password: String,
}

impl Auth {
    fn authorize(&self, context: &Context, activity: &str, check_role: fn(&Role) -> bool) -> FieldResult<()> {
        let auth_user = context.users.get(self.username.as_str())
            .ok_or(FieldError::new(
                    format!("Couldn't verify {}", activity),
                    graphql_value!({ "internal error": "Auth user doesn't exist in database" }),
           ))?;
        if !check_role(&auth_user.0.role) {
            return Err(FieldError::new(
                format!("Couldn't verify {}", activity),
                graphql_value!({ "internal error": "Auth user doesn't have permissions" }),
            ));
        }
        if !User::authorize(
            &context.argon2,
            auth_user.1,
            self.password.as_bytes()
        ) {
            return Err(FieldError::new(
                format!("Couldn't verify {}", activity),
                graphql_value!({ "internal error": "Given authentication credentials couldn't be verified" })
            ));
        }
        Ok(())
    }
}

pub struct QueryRoot;

#[juniper::graphql_object(context = Context)]
impl QueryRoot {
    fn users(context: &Context, auth: Auth) -> FieldResult<Vec<&User>> {
        auth.authorize(context, "getting users", |role| true)?;
        Ok(context.users
            .values()
            .map(|user| &user.0)
            .collect())
    }

    fn user(context: &Context, auth: Auth, name: String) -> FieldResult<&User> {
        auth.authorize(context, format!("getting user '{}'", name).as_str(), |role| true)?;
        if let Some(user) = context.users.get(name.as_str()) {
            Ok(&user.0)
        } else {
            Err(FieldError::new(
                format!("Couldn't retrieve user '{}'", name),
                graphql_value!({ "internal error": "User doesn't exist" }),
            ))
        }
    }

    fn posts(context: &Context, options: PostSearchOptions) -> Vec<&Post> {
        options.with_context(context, false)
    }

    fn post(context: &Context, id: i32) -> FieldResult<&Post> {
        context.published_posts.get(&id).ok_or(FieldError::new(
            format!("Couldn't retrieve post with id '{}'", id),
            graphql_value!({ "internal error": "Post with id doesn't exist" }),
        ))
    }

    fn archived_posts(context: &Context, auth: Auth, options: PostSearchOptions) -> FieldResult<Vec<&Post>> {
        auth.authorize(context, "getting archived posts", |role| true)?;
        Ok(options.with_context(context, true))
    }

    fn archived_post(context: &Context, auth: Auth, id: i32) -> FieldResult<&Post> {
        auth.authorize(context, "getting archived post", |role| true)?;
        context.archived_posts.get(&id).ok_or(FieldError::new(
            format!("Couldn't retrieved archived post with id '{}'", id),
            graphql_value!({ "internal error": "Archived post with id doesn't exist" }),
        ))
    }
}

pub struct MutationRoot;

#[juniper::graphql_object(context = Context)]
impl MutationRoot {
    async fn new_user(context: &mut Context, auth: Auth, new: NewUser) -> FieldResult<&User> {
        auth.authorize(context, "creating user", |role| role.admin)?;
        let password_hash = User::generate_auth(&context.argon2, new.password.as_bytes())
            .or(Err(FieldError::new(
                "Given password was not valid",
                graphql_value!({ "internal error": "Password couldn't be hashed" })
            )))?;
        query!(r#"
            INSERT INTO users (name, created, role, password_hash)
            VALUES (?, datetime('now'), ?, ?)
        "#, new.name, new.role, password_hash)
            .execute(&context.pool)
            .await?;
        let user = User::new(
            new.name,
            FixedOffset::east(0).datetime_from_str(
                query!("SELECT * FROM users WHERE name = ?", new.name)
                    .fetch_one(&context.pool)
                    .await?
                    .created
                    .as_str(),
                "%+",
            )?,
            context.roles
                .get(new.role.as_str())
                .ok_or(FieldError::new(
                    format!("Couldn't get role for user '{}'", new.name),
                    graphql_value!({ "internal error": "Role doesn't exist" }),
                ))?
        );
        context.users.insert(new.name, (user, password_hash));
        Ok(&user)
    }

    async fn new_post(context: &mut Context, auth: Auth, new: NewPost) -> FieldResult<&Post> {
        auth.authorize(context, "creating post", |role| role.post)?;
        query!(r#"
            INSERT INTO posts (published, title, subtitle, author, content, corrections, archived, category)
            VALUES (datetime('now'), ?, ?, ?, ?, "[]", 0, ?)
        "#, new.title, new.subtitle, auth.username, new.content, new.category)
            .execute(&context.pool)
            .await?;
        let db_post = query!("SELECT id, published FROM posts WHERE title = ?", new.title)
            .fetch_one(&context.pool)
            .await?;
        let post = Post::new(
            FixedOffset::east(0).datetime_from_str(db_post.published.as_str(), "%+")?,
            new.title,
            new.subtitle,
            &context.users.get(auth.username.as_str())
                .ok_or(FieldError::new(
                    format!("Given author doesn't exist for post '{}'", new.title),
                    graphql_value!({ "internal error": "Couldn't retrieve author from database" }),
                ))?.0,
            new.content,
            Vec::new(),
            new.category,
            false,
        );
        context.published_posts.insert(db_post.id as i32, post);
        Ok(&post)
    }

    async fn correct(context: &mut Context, auth: Auth, id: i32, correction: String) -> FieldResult<&Post> {
        auth.authorize(context, "correcting post", |role| role.correct)?;
        let post = context.published_posts.get(&id)
            .ok_or(FieldError::new(
                "Couldn't correct post",
                graphql_value!({ "internal error": "There was a problem correcting the post from published" }),
            ))?;
        post.corrections.push(correction);
        query!("UPDATE posts SET corrections = ? WHERE id = ?", serde_json::to_string(&post.corrections)?, id)
            .execute(&context.pool)
            .await?;
        Ok(post)
    }
    
    async fn archive(context: &mut Context, auth: Auth, id: i32) -> FieldResult<&Post> {
        auth.authorize(context, "archiving post", |role| role.archive)?;
        let post = context.published_posts
            .remove(&id)
            .ok_or(FieldError::new(
                "Couldn't archive post",
                graphql_value!({ "internal error": "There was a problem archiving the post from published" }),
            ))?;
        context.archived_posts.insert(id, post);
        query!("UPDATE posts SET archived = 1 WHERE id = ?", id)
            .execute(&context.pool)
            .await?;
        Ok(&post)
    }
    
    async fn delete(context: &mut Context, auth: Auth, id: i32) -> FieldResult<&Post> {
        auth.authorize(context, "deleting post", |role| role.delete)?;
        if let Some(post) = context.published_posts.remove(&id) {
            Ok(&post)
        } else if let Some(post) = context.archived_posts.remove(&id) {
            Ok(&post)
        } else {
            Err(FieldError::new(
                "Couldn't remove post using given post id",
                graphql_value!({ "internal error": "There is no post with given id" }),
            ))
        }
    }
}

pub type Schema = RootNode<'static, QueryRoot, MutationRoot, EmptySubscription<Context>>;

pub fn create_schema() -> Schema {
    Schema::new(QueryRoot {}, MutationRoot {}, EmptySubscription::new())
}
