table! {
    badge (id) {
        id -> Integer,
        friendly_name -> Varchar,
        display_name -> Varchar,
    }
}

table! {
    map (id) {
        id -> Integer,
        status -> Varchar,
        name -> Varchar,
        segment_count -> Integer,
        path -> Nullable<Varchar>,
    }
}

table! {
    password_reset (id) {
        id -> Integer,
        userid -> Integer,
        token -> Varchar,
        valid_until -> Datetime,
    }
}

table! {
    replay (id) {
        id -> Integer,
        scoreid -> Integer,
        path -> Varchar,
    }
}

table! {
    role (id) {
        id -> Integer,
        friendly_name -> Varchar,
        display_name -> Varchar,
    }
}

table! {
    score (id) {
        id -> Integer,
        userid -> Integer,
        mapid -> Integer,
        segment_times -> Varchar,
        strafes -> Integer,
        jumps -> Integer,
        total_time -> Float,
        max_speed -> Float,
        average_speed -> Float,
        season -> Integer,
    }
}

table! {
    season (id) {
        id -> Integer,
        display_name -> Varchar,
        friendly_name -> Varchar,
        ends_at -> Nullable<Datetime>,
    }
}

table! {
    user (id) {
        id -> Integer,
        username -> Varchar,
        email -> Varchar,
        password -> Nullable<Varchar>,
        token -> Nullable<Varchar>,
    }
}

table! {
    user_badge (id) {
        id -> Integer,
        userid -> Integer,
        badgeid -> Integer,
    }
}

table! {
    user_role (id) {
        id -> Integer,
        userid -> Integer,
        roleid -> Integer,
    }
}

table! {
    user_stat (id) {
        id -> Integer,
        userid -> Integer,
        jumps -> Bigint,
        strafes -> Bigint,
    }
}

joinable!(password_reset -> user (userid));
joinable!(replay -> score (scoreid));
joinable!(score -> map (mapid));
joinable!(score -> season (season));
joinable!(score -> user (userid));
joinable!(user_badge -> badge (badgeid));
joinable!(user_badge -> user (userid));
joinable!(user_role -> role (roleid));
joinable!(user_role -> user (userid));
joinable!(user_stat -> user (userid));

allow_tables_to_appear_in_same_query!(
    badge,
    map,
    password_reset,
    replay,
    role,
    score,
    season,
    user,
    user_badge,
    user_role,
    user_stat,
);
