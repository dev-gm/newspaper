use std::collections::HashMap;
use chrono::{
    DateTime,
    FixedOffset,
    NaiveDateTime,
    TimeZone
};
use juniper::{
    GraphQLObject,
    GraphQLInputObject,
    ID,
    RootNode,
    EmptySubscription
};
use bson::{
    Bson,
    Document,
    Array,
};
use std::sync::{ Arc, Mutex };
use std::convert::TryFrom;
use std::fs::File;
use std::path::PathBuf;

struct Database {
    file: File,
    document: Document,
}

impl Database {
    fn initialize(path: PathBuf, document: Document) -> Result<Self, String> {
        let mut file = File::create(path)
            .or(Err(format!("Couldn't create file at {:?}", path)))?;
        document.to_writer(&mut file)
            .or(Err(format!("Couldn't write document \n{}\n to file {:?}", document, file)))?;
        Ok(Self { file, document })
    }

    fn open(path: PathBuf) -> Result<Self, String> {
        let mut file = File::open(path)
            .or(Err(format!("Couldn't open file at {:?}", path)))?;
        let document = Document::from_reader(&mut file)
            .or(Err(format!("Couldn't read document from file {:?}", path)))?;
        Ok(Self { file, document })
    }

    fn update(&mut self) -> Result<(), ()> {
        self.document.to_writer(&mut self.file).or(Err(()))
    }

    fn select(&self, levels: Vec<&str>) -> Option<&Bson> {
        let mut current = &self.document;
        for level in levels[..levels.len()-1].iter() {
            current = if let Ok(current) = current.get_document(level) {
                current
            } else {
                return None;
            }
        }
        current.get(levels[levels.len()-1])
    }

    fn select_mut(&mut self, levels: Vec<&str>) -> Option<&mut Bson> {
        let mut current = &self.document;
        for level in levels[..levels.len()-1].iter() {
            current = if let Ok(current) = current.get_document_mut(level) {
                current
            } else {
                return None;
            }
        }
        current.get_mut(levels[levels.len()-1])
    }

    fn insert(&mut self, levels: Vec<&str>, new: (&str, Bson)) -> Result<Option<Bson>, ()> { // returns old value if item already existed
        let parent = self.select_mut(levels)
            .ok_or(())?
            .as_document_mut()
            .ok_or(())?;
        let out = parent.insert(new.0, new.1);
        self.update()?;
        Ok(out)
    }
}

struct Context {
    database: Arc<Mutex<Database>>,
    users: HashMap<String, User>,
    permissions: HashMap<String, Permissions>,
    articles: HashMap<String, Article>, // key is ID
    archived_articles: HashMap<String, Article>, // key is ID
    categories: HashMap<String, Vec<&'static Article>>,
}

impl Context {
    fn new(database: Database) -> Result<Self, String> {
        let context = Self {
            database: Arc::new(Mutex::new(database)),
            users: HashMap::new(),
            permissions: HashMap::new(),
            articles: HashMap::new(),
            archived_articles: HashMap::new(),
            categories: HashMap::new(),
        };
        User::all_bson_into_context(
            database
                .select(vec!["users"])
                .ok_or(String::from("'users' was not present at top level of database"))?
                .as_document()
                .ok_or(String::from("'users' was present in database, but was not a document"))?,
            &context
        )?;
        Ok(context)
    }
}

trait BsonIntoContext {
    fn bson_into_context(key: String, value: &Document, context: &'static Context) -> Result<&'static Self, String>;

    fn all_bson_into_context(input: &Document, context: &'static Context) -> Result<Vec<&'static Self>, String> {
        let mut out = Vec::new();
        for (key, value) in input.iter() {
            out.push(Self::bson_into_context(
                *key,
                value
                    .as_document()
                    .ok_or(format!("Couldn't get document associated with '{}' in database", key))?,
                context
            )?)
        }
        Ok(out)
    }
}

#[derive(GraphQLObject)]
struct User {
    created: DateTime<FixedOffset>,
    permissions: &'static Permissions,
}

impl BsonIntoContext for User {
    fn bson_into_context(name: String, value: &Document, context: &'static Context) -> Result<&'static Self, String> {
        context.users.insert(name, Self {
            created: FixedOffset
                ::east(0)
                .from_utc_datetime(
                    &value
                        .get_datetime("created")
                        .or(Err(format!("Couldn't get 'created' from '{}' user entry in database", name)))?
                        .naive_utc()
                ),
            permissions: context.permissions.get(
                value
                    .get_str("permissions")
                    .or(Err(format!("Couldn't get 'permissions' from '{}' user entry in database", name)))?
            ).ok_or(format!("Couldn't retrieve permissions for user '{}' from permissions array", name))?,
        });
        context.users.get(name.as_str()).ok_or(format!("Failed to create user '{}' from database", name))
    }
}

#[derive(GraphQLInputObject)]
struct NewUser {
    created: NaiveDateTime,
    permissions: NewPermissions,
}

#[derive(GraphQLObject)]
struct Permissions {
    read: bool, // read versions and backend dashboard
    post: bool, // post an article and edit your own articles
    edit: bool, // rename, edit, change categories, and revert all articles
    archive: bool, // archive all articles (this should be used instead of deleting)
    delete: bool, // permanently delete all articles
    admin: bool, // change permissions of all non-admin/non-owner users
    owner: bool, // change permissions of all admins and themselves
}

impl BsonIntoContext for Permissions {
    fn bson_into_context(name: String, value: &Document, context: &'static Context) -> Result<&'static Self, String> {
        context.permissions.insert(name, Self {
            read: value.get_bool("read")
                .or(Err(format!("Couldn't get 'read' permission for permissions profile '{}' from database", name)))?,
            post: value.get_bool("post")
                .or(Err(format!("Couldn't get 'post' permission for permissions profile '{}' from database", name)))?,
            edit: value.get_bool("edit")
                .or(Err(format!("Couldn't get 'edit' permission for permissions profile '{}' from database", name)))?,
            archive: value.get_bool("archive")
                .or(Err(format!("Couldn't get 'archive' permission for permissions profile '{}' from database", name)))?,
            delete: value.get_bool("delete")
                .or(Err(format!("Couldn't get 'delete' permission for permissions profile '{}' from database", name)))?,
            admin: value.get_bool("admin")
                .or(Err(format!("Couldn't get 'admin' permission for permissions profile '{}' from database", name)))?,
            owner: value.get_bool("owner")
                .or(Err(format!("Couldn't get 'owner' permission for permissions profile '{}' from database", name)))?,
        });
        context.permissions.get(name.as_str()).ok_or(format!("Failed to create permissions profile '{}' from database", name))
    }
}

#[derive(GraphQLInputObject)]
struct NewPermissions {
    read: bool,
    post: bool,
    edit: bool,
    archive: bool,
    delete: bool,
    admin: bool,
    owner: bool,
}

#[derive(GraphQLObject)]
struct Article {
    published: DateTime<FixedOffset>,
    title: String,
    subtitle: Option<String>,
    author: &'static User,
    content: ArticleContent, // in markdown
}

impl BsonIntoContext for Article {
    fn bson_into_context(id: String, value: &Document, context: &'static Context) -> Result<&'static Self, String> {
        let article = Self {
            published: FixedOffset
                ::east(0)
                .from_utc_datetime(
                    &value
                        .get_datetime("published")
                        .or(Err(format!("Couldn't get 'published' for article with id '{}'", id)))?
                        .naive_utc()
                ),
            title: String::from(value
                .get_str("title")
                .or(Err(format!("Couldn't get 'title' for article with id '{}'", id)))?
            ),
            subtitle: match value.get_str("subtitle") {
                Ok(subtitle) => Some(String::from(subtitle)),
                Err(_) => None
            },
            author: context.users.get(value
                .get_str("author")
                .or(Err(format!("Couldn't get 'author' for article with id '{}'", id)))?
            ).ok_or(format!("Couldn't get author for article with id '{}' from users array", id))?,
            content: ArticleContent::try_from(value
                .get_document("content")
                .or(Err(format!("Couldn't get 'published' for article with id '{}'", id)))?
            ),
        };
        match value.get_bool("archived") {
            Ok(true) => {
                context.archived_articles.insert(id, article);
                context.archived_articles.get(&id)
                    .ok_or(String::from("Archived article could not be retrieved from database properly"))
            },
            _ => {
                context.articles.insert(id, article);
                context.articles.get(&id)
                    .ok_or(String::from("Article could not be retrieved from database properly"))
            },
        }
    }
}

#[derive(GraphQLInputObject)]
struct NewArticle {
    published: NaiveDateTime,
    title: String,
    subtitle: Option<String>,
    author: String,
    content: String,
    categories: Vec<String>,
}

#[derive(GraphQLObject)]
struct ArticleContent {
    init: String,
    changes: Vec<ArticleChange>,
}

impl TryFrom<&Document> for ArticleContent {
    fn try_from(value: &Document) -> Result<Self, String> {
        Ok(Self {
            init: String::from(value
                .get_str("init")
                .or(Err(String::from("Couldn't get 'init' for content for a post")))?
            ),
            changes: value.get_array("changes")
                .or(Err(String::from("Couldn't get 'changes' for content for a post")))?
                .iter()
                .map(|change| Ok(ArticleChange::try_from(change
                    .as_document()
                    .ok_or(String::from("Couldn't get a change in 'changes' for content for a post"))?
                )))
                .collect::<Result<Vec<ArticleChange>, String>>()?
        })
    }
}

#[derive(GraphQLObject)]
struct ArticleChange {
    begin: ArticlePos,
    end: ArticlePos,
    inserted: String,
}

impl TryFrom<&Document> for ArticleChange {
    fn try_from(value: &Document) -> Result<Self, String> {
        Ok(Self {
            begin: ArticlePos::try_from(value
                .get_array("begin")
                .or(Err(String::from("'begin' in a change in article content couldn't be retrieved")))?
            ),
            end: ArticlePos::try_from(value
                .get_array("end")
                .or(Err(String::from("'end' in a change in article content couldn't be retrieved")))?
            ),
            inserted: String::from(value
                .get_str("inserted")
                .or(Err(String::from("'inserted' in a change in article content couldn't be retrieved")))?
            ),
        })
    }
}

impl TryFrom<&Array> for ArticleChange {
    fn try_from(value: &Array) -> Result<Vec<Self>, String> {
        let mut out = Vec::new();
        for version in value {
            out.push(Self::try_from(
                version.as_document()
                    .ok_or(format!("Version for content for an article isn't a document"))?,
            ));
        }
        Ok(out)
    }
}

#[derive(GraphQLObject)]
struct ArticlePos {
    line: i32,
    column: i32,
}

impl TryFrom<&Array> for ArticlePos {
    fn try_from(value: &Array) -> Result<Self, String> {
        Ok(Self {
            line: value.get(0)
                .ok_or(String::from("[0] couldn't be retrieved from an ArticlePos"))?
                .as_i32()
                .ok_or(String::from("[0] in an ArticlePos wasn't an i32"))?,
            column: value.get(1)
                .ok_or(String::from("[1] couldn't be retrieved from an ArticlePos"))?
                .as_i32()
                .ok_or(String::from("[1] in an ArticlePos wasn't an i32"))?,
        })
    }
}

pub struct Query;

#[juniper::graphql_object(context = Context)]
impl Query {}

pub struct Mutation;

#[juniper::graphql_object(context = Context)]
impl Mutation {}

pub type Schema = RootNode<'static, Query, Mutation, EmptySubscription>;

pub fn create_schema() -> Schema {
    Schema::new(Query {}, Mutation {}, EmptySubscription::new())
}