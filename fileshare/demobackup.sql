PGDMP                      }            demodb    17.5    17.5 �    �           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                           false            �           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                           false            �           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                           false            �           1262    16387    demodb    DATABASE     �   CREATE DATABASE demodb WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_United States.1252';
    DROP DATABASE demodb;
                     postgres    false            �           1247    16701    sensitivity    TYPE     P   CREATE TYPE public.sensitivity AS ENUM (
    'High',
    'Medium',
    'Low'
);
    DROP TYPE public.sensitivity;
       public               postgres    false            �           1247    24928    share_status    TYPE     L   CREATE TYPE public.share_status AS ENUM (
    'Internal',
    'External'
);
    DROP TYPE public.share_status;
       public               postgres    false            �           1247    24922    status    TYPE     ;   CREATE TYPE public.status AS ENUM (
    'yes',
    'no'
);
    DROP TYPE public.status;
       public               postgres    false            �            1255    16727    allow_doc_type()    FUNCTION     3  CREATE FUNCTION public.allow_doc_type() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    allowed_types TEXT[];
BEGIN
    SELECT allowed_file_type INTO allowed_types
    FROM organization
    WHERE org_tag = NEW.org_tag;

    IF allowed_types IS NULL THEN
        RAISE EXCEPTION 'Organization % not found or has no allowed types', NEW.org_tag;
    END IF;

    IF NOT (NEW.doc_type = ANY(allowed_types)) THEN
        RAISE EXCEPTION 'Invalid doc_type: %, not allowed for organization %', NEW.doc_type, NEW.org_tag;
    END IF;

    RETURN NEW;
END;
$$;
 '   DROP FUNCTION public.allow_doc_type();
       public               postgres    false            �            1255    16726    validate_doc_type()    FUNCTION     F  CREATE FUNCTION public.validate_doc_type() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    allowed_types TEXT[];
BEGIN
    SELECT allowed_file_type INTO allowed_types
    FROM organization
    WHERE org_tag = NEW.org_tag;

    IF allowed_types IS NULL THEN
        RAISE EXCEPTION 'Organization % not found or has no allowed types', NEW.organization_id;
    END IF;

    IF NOT (NEW.doc_type = ANY(allowed_types)) THEN
        RAISE EXCEPTION 'Invalid doc_type: %, not allowed for organization %', NEW.doc_type, NEW.organization_id;
    END IF;

    RETURN NEW;
END;
$$;
 *   DROP FUNCTION public.validate_doc_type();
       public               postgres    false            �            1259    16506 
   auth_group    TABLE     f   CREATE TABLE public.auth_group (
    id integer NOT NULL,
    name character varying(150) NOT NULL
);
    DROP TABLE public.auth_group;
       public         heap r       postgres    false            �            1259    16505    auth_group_id_seq    SEQUENCE     �   CREATE SEQUENCE public.auth_group_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.auth_group_id_seq;
       public               postgres    false    226            �           0    0    auth_group_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.auth_group_id_seq OWNED BY public.auth_group.id;
          public               postgres    false    225            �            1259    16515    auth_group_permissions    TABLE     �   CREATE TABLE public.auth_group_permissions (
    id bigint NOT NULL,
    group_id integer NOT NULL,
    permission_id integer NOT NULL
);
 *   DROP TABLE public.auth_group_permissions;
       public         heap r       postgres    false            �            1259    16514    auth_group_permissions_id_seq    SEQUENCE     �   CREATE SEQUENCE public.auth_group_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 4   DROP SEQUENCE public.auth_group_permissions_id_seq;
       public               postgres    false    228            �           0    0    auth_group_permissions_id_seq    SEQUENCE OWNED BY     _   ALTER SEQUENCE public.auth_group_permissions_id_seq OWNED BY public.auth_group_permissions.id;
          public               postgres    false    227            �            1259    16499    auth_permission    TABLE     �   CREATE TABLE public.auth_permission (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    content_type_id integer NOT NULL,
    codename character varying(100) NOT NULL
);
 #   DROP TABLE public.auth_permission;
       public         heap r       postgres    false            �            1259    16498    auth_permission_id_seq    SEQUENCE     �   CREATE SEQUENCE public.auth_permission_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE public.auth_permission_id_seq;
       public               postgres    false    224            �           0    0    auth_permission_id_seq    SEQUENCE OWNED BY     Q   ALTER SEQUENCE public.auth_permission_id_seq OWNED BY public.auth_permission.id;
          public               postgres    false    223            �            1259    16522 	   auth_user    TABLE     �  CREATE TABLE public.auth_user (
    id integer NOT NULL,
    password character varying(128) NOT NULL,
    last_login timestamp with time zone,
    is_superuser boolean NOT NULL,
    username character varying(150) NOT NULL,
    first_name character varying(150) NOT NULL,
    last_name character varying(150) NOT NULL,
    email character varying(254) NOT NULL,
    is_staff boolean NOT NULL,
    is_active boolean NOT NULL,
    date_joined timestamp with time zone NOT NULL
);
    DROP TABLE public.auth_user;
       public         heap r       postgres    false            �            1259    16531    auth_user_groups    TABLE     ~   CREATE TABLE public.auth_user_groups (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    group_id integer NOT NULL
);
 $   DROP TABLE public.auth_user_groups;
       public         heap r       postgres    false            �            1259    16530    auth_user_groups_id_seq    SEQUENCE     �   CREATE SEQUENCE public.auth_user_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.auth_user_groups_id_seq;
       public               postgres    false    232            �           0    0    auth_user_groups_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.auth_user_groups_id_seq OWNED BY public.auth_user_groups.id;
          public               postgres    false    231            �            1259    16521    auth_user_id_seq    SEQUENCE     �   CREATE SEQUENCE public.auth_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.auth_user_id_seq;
       public               postgres    false    230            �           0    0    auth_user_id_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.auth_user_id_seq OWNED BY public.auth_user.id;
          public               postgres    false    229            �            1259    16538    auth_user_user_permissions    TABLE     �   CREATE TABLE public.auth_user_user_permissions (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    permission_id integer NOT NULL
);
 .   DROP TABLE public.auth_user_user_permissions;
       public         heap r       postgres    false            �            1259    16537 !   auth_user_user_permissions_id_seq    SEQUENCE     �   CREATE SEQUENCE public.auth_user_user_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 8   DROP SEQUENCE public.auth_user_user_permissions_id_seq;
       public               postgres    false    234            �           0    0 !   auth_user_user_permissions_id_seq    SEQUENCE OWNED BY     g   ALTER SEQUENCE public.auth_user_user_permissions_id_seq OWNED BY public.auth_user_user_permissions.id;
          public               postgres    false    233            �            1259    16597    django_admin_log    TABLE     �  CREATE TABLE public.django_admin_log (
    id integer NOT NULL,
    action_time timestamp with time zone NOT NULL,
    object_id text,
    object_repr character varying(200) NOT NULL,
    action_flag smallint NOT NULL,
    change_message text NOT NULL,
    content_type_id integer,
    user_id integer NOT NULL,
    CONSTRAINT django_admin_log_action_flag_check CHECK ((action_flag >= 0))
);
 $   DROP TABLE public.django_admin_log;
       public         heap r       postgres    false            �            1259    16596    django_admin_log_id_seq    SEQUENCE     �   CREATE SEQUENCE public.django_admin_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.django_admin_log_id_seq;
       public               postgres    false    236            �           0    0    django_admin_log_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.django_admin_log_id_seq OWNED BY public.django_admin_log.id;
          public               postgres    false    235            �            1259    16490    django_content_type    TABLE     �   CREATE TABLE public.django_content_type (
    id integer NOT NULL,
    app_label character varying(100) NOT NULL,
    model character varying(100) NOT NULL
);
 '   DROP TABLE public.django_content_type;
       public         heap r       postgres    false            �            1259    16489    django_content_type_id_seq    SEQUENCE     �   CREATE SEQUENCE public.django_content_type_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 1   DROP SEQUENCE public.django_content_type_id_seq;
       public               postgres    false    222            �           0    0    django_content_type_id_seq    SEQUENCE OWNED BY     Y   ALTER SEQUENCE public.django_content_type_id_seq OWNED BY public.django_content_type.id;
          public               postgres    false    221            �            1259    16481    django_migrations    TABLE     �   CREATE TABLE public.django_migrations (
    id bigint NOT NULL,
    app character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    applied timestamp with time zone NOT NULL
);
 %   DROP TABLE public.django_migrations;
       public         heap r       postgres    false            �            1259    16480    django_migrations_id_seq    SEQUENCE     �   CREATE SEQUENCE public.django_migrations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 /   DROP SEQUENCE public.django_migrations_id_seq;
       public               postgres    false    220            �           0    0    django_migrations_id_seq    SEQUENCE OWNED BY     U   ALTER SEQUENCE public.django_migrations_id_seq OWNED BY public.django_migrations.id;
          public               postgres    false    219            �            1259    16626    django_session    TABLE     �   CREATE TABLE public.django_session (
    session_key character varying(40) NOT NULL,
    session_data text NOT NULL,
    expire_date timestamp with time zone NOT NULL
);
 "   DROP TABLE public.django_session;
       public         heap r       postgres    false            �            1259    16707 	   documents    TABLE     �  CREATE TABLE public.documents (
    doc_id text NOT NULL,
    doc_name character varying(300),
    doc_title text,
    doc_type text,
    doc_group text,
    uploaded_user text NOT NULL,
    encryption_key text NOT NULL,
    file_senstivity public.sensitivity DEFAULT 'High'::public.sensitivity NOT NULL,
    uploaded_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    org_tag text
);
    DROP TABLE public.documents;
       public         heap r       postgres    false    920    920            �            1259    16423    organization    TABLE     3  CREATE TABLE public.organization (
    organization_id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_name text,
    allowed_file_type text[] NOT NULL,
    role_hierarchy text[] NOT NULL,
    org_domain text,
    shareable_organizations text[],
    org_tag text NOT NULL,
    file_size bigint
);
     DROP TABLE public.organization;
       public         heap r       postgres    false            �            1259    16636    share_files_myuser    TABLE     O  CREATE TABLE public.share_files_myuser (
    password character varying(128) NOT NULL,
    last_login timestamp with time zone,
    is_superuser boolean NOT NULL,
    user_id character varying(255) NOT NULL,
    user_name character varying(100) NOT NULL,
    email character varying(200) NOT NULL,
    phone_no character varying(30) NOT NULL,
    organization_id uuid,
    google_id character varying(255),
    auth_id character varying(255),
    auth_provider character varying(50) NOT NULL,
    role character varying(100),
    is_active boolean NOT NULL,
    is_staff boolean NOT NULL
);
 &   DROP TABLE public.share_files_myuser;
       public         heap r       postgres    false            �            1259    16652    share_files_myuser_groups    TABLE     �   CREATE TABLE public.share_files_myuser_groups (
    id bigint NOT NULL,
    myuser_id character varying(255) NOT NULL,
    group_id integer NOT NULL
);
 -   DROP TABLE public.share_files_myuser_groups;
       public         heap r       postgres    false            �            1259    16651     share_files_myuser_groups_id_seq    SEQUENCE     �   CREATE SEQUENCE public.share_files_myuser_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 7   DROP SEQUENCE public.share_files_myuser_groups_id_seq;
       public               postgres    false    240            �           0    0     share_files_myuser_groups_id_seq    SEQUENCE OWNED BY     e   ALTER SEQUENCE public.share_files_myuser_groups_id_seq OWNED BY public.share_files_myuser_groups.id;
          public               postgres    false    239            �            1259    16659 #   share_files_myuser_user_permissions    TABLE     �   CREATE TABLE public.share_files_myuser_user_permissions (
    id bigint NOT NULL,
    myuser_id character varying(255) NOT NULL,
    permission_id integer NOT NULL
);
 7   DROP TABLE public.share_files_myuser_user_permissions;
       public         heap r       postgres    false            �            1259    16658 *   share_files_myuser_user_permissions_id_seq    SEQUENCE     �   CREATE SEQUENCE public.share_files_myuser_user_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 A   DROP SEQUENCE public.share_files_myuser_user_permissions_id_seq;
       public               postgres    false    242            �           0    0 *   share_files_myuser_user_permissions_id_seq    SEQUENCE OWNED BY     y   ALTER SEQUENCE public.share_files_myuser_user_permissions_id_seq OWNED BY public.share_files_myuser_user_permissions.id;
          public               postgres    false    241            �            1259    33113    shared_documents    TABLE     �  CREATE TABLE public.shared_documents (
    doc_id text,
    shared_user_id text,
    shared_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    shared_status public.share_status,
    access_token text,
    access_status public.status DEFAULT 'no'::public.status,
    download_count integer,
    current_download_count integer DEFAULT 0,
    time_limit interval,
    shared_by_user_id text
);
 $   DROP TABLE public.shared_documents;
       public         heap r       postgres    false    926    929    926            �            1259    16432    users    TABLE     [  CREATE TABLE public.users (
    user_id text NOT NULL,
    user_name character varying(100) NOT NULL,
    user_password text,
    email character varying(200) NOT NULL,
    phone_no character varying(30) NOT NULL,
    google_id text,
    auth_id text,
    auth_provider text DEFAULT 'local'::text,
    user_role text NOT NULL,
    org_tag text
);
    DROP TABLE public.users;
       public         heap r       postgres    false            �           2604    16509    auth_group id    DEFAULT     n   ALTER TABLE ONLY public.auth_group ALTER COLUMN id SET DEFAULT nextval('public.auth_group_id_seq'::regclass);
 <   ALTER TABLE public.auth_group ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    226    225    226            �           2604    16518    auth_group_permissions id    DEFAULT     �   ALTER TABLE ONLY public.auth_group_permissions ALTER COLUMN id SET DEFAULT nextval('public.auth_group_permissions_id_seq'::regclass);
 H   ALTER TABLE public.auth_group_permissions ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    228    227    228            �           2604    16502    auth_permission id    DEFAULT     x   ALTER TABLE ONLY public.auth_permission ALTER COLUMN id SET DEFAULT nextval('public.auth_permission_id_seq'::regclass);
 A   ALTER TABLE public.auth_permission ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    223    224    224            �           2604    16525    auth_user id    DEFAULT     l   ALTER TABLE ONLY public.auth_user ALTER COLUMN id SET DEFAULT nextval('public.auth_user_id_seq'::regclass);
 ;   ALTER TABLE public.auth_user ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    229    230    230            �           2604    16534    auth_user_groups id    DEFAULT     z   ALTER TABLE ONLY public.auth_user_groups ALTER COLUMN id SET DEFAULT nextval('public.auth_user_groups_id_seq'::regclass);
 B   ALTER TABLE public.auth_user_groups ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    231    232    232            �           2604    16541    auth_user_user_permissions id    DEFAULT     �   ALTER TABLE ONLY public.auth_user_user_permissions ALTER COLUMN id SET DEFAULT nextval('public.auth_user_user_permissions_id_seq'::regclass);
 L   ALTER TABLE public.auth_user_user_permissions ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    233    234    234            �           2604    16600    django_admin_log id    DEFAULT     z   ALTER TABLE ONLY public.django_admin_log ALTER COLUMN id SET DEFAULT nextval('public.django_admin_log_id_seq'::regclass);
 B   ALTER TABLE public.django_admin_log ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    235    236    236            �           2604    16493    django_content_type id    DEFAULT     �   ALTER TABLE ONLY public.django_content_type ALTER COLUMN id SET DEFAULT nextval('public.django_content_type_id_seq'::regclass);
 E   ALTER TABLE public.django_content_type ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    221    222    222            �           2604    16484    django_migrations id    DEFAULT     |   ALTER TABLE ONLY public.django_migrations ALTER COLUMN id SET DEFAULT nextval('public.django_migrations_id_seq'::regclass);
 C   ALTER TABLE public.django_migrations ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    220    219    220            �           2604    16655    share_files_myuser_groups id    DEFAULT     �   ALTER TABLE ONLY public.share_files_myuser_groups ALTER COLUMN id SET DEFAULT nextval('public.share_files_myuser_groups_id_seq'::regclass);
 K   ALTER TABLE public.share_files_myuser_groups ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    240    239    240            �           2604    16662 &   share_files_myuser_user_permissions id    DEFAULT     �   ALTER TABLE ONLY public.share_files_myuser_user_permissions ALTER COLUMN id SET DEFAULT nextval('public.share_files_myuser_user_permissions_id_seq'::regclass);
 U   ALTER TABLE public.share_files_myuser_user_permissions ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    242    241    242            �          0    16506 
   auth_group 
   TABLE DATA           .   COPY public.auth_group (id, name) FROM stdin;
    public               postgres    false    226   ��       �          0    16515    auth_group_permissions 
   TABLE DATA           M   COPY public.auth_group_permissions (id, group_id, permission_id) FROM stdin;
    public               postgres    false    228   ��       �          0    16499    auth_permission 
   TABLE DATA           N   COPY public.auth_permission (id, name, content_type_id, codename) FROM stdin;
    public               postgres    false    224   ��       �          0    16522 	   auth_user 
   TABLE DATA           �   COPY public.auth_user (id, password, last_login, is_superuser, username, first_name, last_name, email, is_staff, is_active, date_joined) FROM stdin;
    public               postgres    false    230   )�       �          0    16531    auth_user_groups 
   TABLE DATA           A   COPY public.auth_user_groups (id, user_id, group_id) FROM stdin;
    public               postgres    false    232   F�       �          0    16538    auth_user_user_permissions 
   TABLE DATA           P   COPY public.auth_user_user_permissions (id, user_id, permission_id) FROM stdin;
    public               postgres    false    234   c�       �          0    16597    django_admin_log 
   TABLE DATA           �   COPY public.django_admin_log (id, action_time, object_id, object_repr, action_flag, change_message, content_type_id, user_id) FROM stdin;
    public               postgres    false    236   ��       �          0    16490    django_content_type 
   TABLE DATA           C   COPY public.django_content_type (id, app_label, model) FROM stdin;
    public               postgres    false    222   ��       �          0    16481    django_migrations 
   TABLE DATA           C   COPY public.django_migrations (id, app, name, applied) FROM stdin;
    public               postgres    false    220   �       �          0    16626    django_session 
   TABLE DATA           P   COPY public.django_session (session_key, session_data, expire_date) FROM stdin;
    public               postgres    false    237   ��       �          0    16707 	   documents 
   TABLE DATA           �   COPY public.documents (doc_id, doc_name, doc_title, doc_type, doc_group, uploaded_user, encryption_key, file_senstivity, uploaded_time, org_tag) FROM stdin;
    public               postgres    false    243   x�       �          0    16423    organization 
   TABLE DATA           �   COPY public.organization (organization_id, organization_name, allowed_file_type, role_hierarchy, org_domain, shareable_organizations, org_tag, file_size) FROM stdin;
    public               postgres    false    217   k�       �          0    16636    share_files_myuser 
   TABLE DATA           �   COPY public.share_files_myuser (password, last_login, is_superuser, user_id, user_name, email, phone_no, organization_id, google_id, auth_id, auth_provider, role, is_active, is_staff) FROM stdin;
    public               postgres    false    238   ��       �          0    16652    share_files_myuser_groups 
   TABLE DATA           L   COPY public.share_files_myuser_groups (id, myuser_id, group_id) FROM stdin;
    public               postgres    false    240   ��       �          0    16659 #   share_files_myuser_user_permissions 
   TABLE DATA           [   COPY public.share_files_myuser_user_permissions (id, myuser_id, permission_id) FROM stdin;
    public               postgres    false    242   ��       �          0    33113    shared_documents 
   TABLE DATA           �   COPY public.shared_documents (doc_id, shared_user_id, shared_at, shared_status, access_token, access_status, download_count, current_download_count, time_limit, shared_by_user_id) FROM stdin;
    public               postgres    false    244   �       �          0    16432    users 
   TABLE DATA           �   COPY public.users (user_id, user_name, user_password, email, phone_no, google_id, auth_id, auth_provider, user_role, org_tag) FROM stdin;
    public               postgres    false    218   ��       �           0    0    auth_group_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.auth_group_id_seq', 1, false);
          public               postgres    false    225            �           0    0    auth_group_permissions_id_seq    SEQUENCE SET     L   SELECT pg_catalog.setval('public.auth_group_permissions_id_seq', 1, false);
          public               postgres    false    227            �           0    0    auth_permission_id_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('public.auth_permission_id_seq', 28, true);
          public               postgres    false    223            �           0    0    auth_user_groups_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.auth_user_groups_id_seq', 1, false);
          public               postgres    false    231            �           0    0    auth_user_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.auth_user_id_seq', 1, false);
          public               postgres    false    229            �           0    0 !   auth_user_user_permissions_id_seq    SEQUENCE SET     P   SELECT pg_catalog.setval('public.auth_user_user_permissions_id_seq', 1, false);
          public               postgres    false    233            �           0    0    django_admin_log_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.django_admin_log_id_seq', 1, false);
          public               postgres    false    235            �           0    0    django_content_type_id_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.django_content_type_id_seq', 7, true);
          public               postgres    false    221            �           0    0    django_migrations_id_seq    SEQUENCE SET     G   SELECT pg_catalog.setval('public.django_migrations_id_seq', 19, true);
          public               postgres    false    219            �           0    0     share_files_myuser_groups_id_seq    SEQUENCE SET     O   SELECT pg_catalog.setval('public.share_files_myuser_groups_id_seq', 1, false);
          public               postgres    false    239            �           0    0 *   share_files_myuser_user_permissions_id_seq    SEQUENCE SET     Y   SELECT pg_catalog.setval('public.share_files_myuser_user_permissions_id_seq', 1, false);
          public               postgres    false    241            �           2606    16624    auth_group auth_group_name_key 
   CONSTRAINT     Y   ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_name_key UNIQUE (name);
 H   ALTER TABLE ONLY public.auth_group DROP CONSTRAINT auth_group_name_key;
       public                 postgres    false    226            �           2606    16554 R   auth_group_permissions auth_group_permissions_group_id_permission_id_0cd325b0_uniq 
   CONSTRAINT     �   ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_group_id_permission_id_0cd325b0_uniq UNIQUE (group_id, permission_id);
 |   ALTER TABLE ONLY public.auth_group_permissions DROP CONSTRAINT auth_group_permissions_group_id_permission_id_0cd325b0_uniq;
       public                 postgres    false    228    228            �           2606    16520 2   auth_group_permissions auth_group_permissions_pkey 
   CONSTRAINT     p   ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_pkey PRIMARY KEY (id);
 \   ALTER TABLE ONLY public.auth_group_permissions DROP CONSTRAINT auth_group_permissions_pkey;
       public                 postgres    false    228            �           2606    16511    auth_group auth_group_pkey 
   CONSTRAINT     X   ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_pkey PRIMARY KEY (id);
 D   ALTER TABLE ONLY public.auth_group DROP CONSTRAINT auth_group_pkey;
       public                 postgres    false    226            �           2606    16545 F   auth_permission auth_permission_content_type_id_codename_01ab375a_uniq 
   CONSTRAINT     �   ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_content_type_id_codename_01ab375a_uniq UNIQUE (content_type_id, codename);
 p   ALTER TABLE ONLY public.auth_permission DROP CONSTRAINT auth_permission_content_type_id_codename_01ab375a_uniq;
       public                 postgres    false    224    224            �           2606    16504 $   auth_permission auth_permission_pkey 
   CONSTRAINT     b   ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_pkey PRIMARY KEY (id);
 N   ALTER TABLE ONLY public.auth_permission DROP CONSTRAINT auth_permission_pkey;
       public                 postgres    false    224            �           2606    16536 &   auth_user_groups auth_user_groups_pkey 
   CONSTRAINT     d   ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_pkey PRIMARY KEY (id);
 P   ALTER TABLE ONLY public.auth_user_groups DROP CONSTRAINT auth_user_groups_pkey;
       public                 postgres    false    232            �           2606    16569 @   auth_user_groups auth_user_groups_user_id_group_id_94350c0c_uniq 
   CONSTRAINT     �   ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_user_id_group_id_94350c0c_uniq UNIQUE (user_id, group_id);
 j   ALTER TABLE ONLY public.auth_user_groups DROP CONSTRAINT auth_user_groups_user_id_group_id_94350c0c_uniq;
       public                 postgres    false    232    232            �           2606    16527    auth_user auth_user_pkey 
   CONSTRAINT     V   ALTER TABLE ONLY public.auth_user
    ADD CONSTRAINT auth_user_pkey PRIMARY KEY (id);
 B   ALTER TABLE ONLY public.auth_user DROP CONSTRAINT auth_user_pkey;
       public                 postgres    false    230            �           2606    16543 :   auth_user_user_permissions auth_user_user_permissions_pkey 
   CONSTRAINT     x   ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_pkey PRIMARY KEY (id);
 d   ALTER TABLE ONLY public.auth_user_user_permissions DROP CONSTRAINT auth_user_user_permissions_pkey;
       public                 postgres    false    234            �           2606    16583 Y   auth_user_user_permissions auth_user_user_permissions_user_id_permission_id_14a6b632_uniq 
   CONSTRAINT     �   ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_user_id_permission_id_14a6b632_uniq UNIQUE (user_id, permission_id);
 �   ALTER TABLE ONLY public.auth_user_user_permissions DROP CONSTRAINT auth_user_user_permissions_user_id_permission_id_14a6b632_uniq;
       public                 postgres    false    234    234            �           2606    16619     auth_user auth_user_username_key 
   CONSTRAINT     _   ALTER TABLE ONLY public.auth_user
    ADD CONSTRAINT auth_user_username_key UNIQUE (username);
 J   ALTER TABLE ONLY public.auth_user DROP CONSTRAINT auth_user_username_key;
       public                 postgres    false    230            �           2606    16605 &   django_admin_log django_admin_log_pkey 
   CONSTRAINT     d   ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_pkey PRIMARY KEY (id);
 P   ALTER TABLE ONLY public.django_admin_log DROP CONSTRAINT django_admin_log_pkey;
       public                 postgres    false    236            �           2606    16497 E   django_content_type django_content_type_app_label_model_76bd3d3b_uniq 
   CONSTRAINT     �   ALTER TABLE ONLY public.django_content_type
    ADD CONSTRAINT django_content_type_app_label_model_76bd3d3b_uniq UNIQUE (app_label, model);
 o   ALTER TABLE ONLY public.django_content_type DROP CONSTRAINT django_content_type_app_label_model_76bd3d3b_uniq;
       public                 postgres    false    222    222            �           2606    16495 ,   django_content_type django_content_type_pkey 
   CONSTRAINT     j   ALTER TABLE ONLY public.django_content_type
    ADD CONSTRAINT django_content_type_pkey PRIMARY KEY (id);
 V   ALTER TABLE ONLY public.django_content_type DROP CONSTRAINT django_content_type_pkey;
       public                 postgres    false    222            �           2606    16488 (   django_migrations django_migrations_pkey 
   CONSTRAINT     f   ALTER TABLE ONLY public.django_migrations
    ADD CONSTRAINT django_migrations_pkey PRIMARY KEY (id);
 R   ALTER TABLE ONLY public.django_migrations DROP CONSTRAINT django_migrations_pkey;
       public                 postgres    false    220            �           2606    16632 "   django_session django_session_pkey 
   CONSTRAINT     i   ALTER TABLE ONLY public.django_session
    ADD CONSTRAINT django_session_pkey PRIMARY KEY (session_key);
 L   ALTER TABLE ONLY public.django_session DROP CONSTRAINT django_session_pkey;
       public                 postgres    false    237                       2606    16715    documents documents_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_pkey PRIMARY KEY (doc_id);
 B   ALTER TABLE ONLY public.documents DROP CONSTRAINT documents_pkey;
       public                 postgres    false    243            �           2606    16431 (   organization organization_org_domain_key 
   CONSTRAINT     i   ALTER TABLE ONLY public.organization
    ADD CONSTRAINT organization_org_domain_key UNIQUE (org_domain);
 R   ALTER TABLE ONLY public.organization DROP CONSTRAINT organization_org_domain_key;
       public                 postgres    false    217            �           2606    16454 %   organization organization_org_tag_key 
   CONSTRAINT     c   ALTER TABLE ONLY public.organization
    ADD CONSTRAINT organization_org_tag_key UNIQUE (org_tag);
 O   ALTER TABLE ONLY public.organization DROP CONSTRAINT organization_org_tag_key;
       public                 postgres    false    217            �           2606    16429    organization organization_pkey 
   CONSTRAINT     i   ALTER TABLE ONLY public.organization
    ADD CONSTRAINT organization_pkey PRIMARY KEY (organization_id);
 H   ALTER TABLE ONLY public.organization DROP CONSTRAINT organization_pkey;
       public                 postgres    false    217                        2606    16650 1   share_files_myuser share_files_myuser_auth_id_key 
   CONSTRAINT     o   ALTER TABLE ONLY public.share_files_myuser
    ADD CONSTRAINT share_files_myuser_auth_id_key UNIQUE (auth_id);
 [   ALTER TABLE ONLY public.share_files_myuser DROP CONSTRAINT share_files_myuser_auth_id_key;
       public                 postgres    false    238                       2606    16644 /   share_files_myuser share_files_myuser_email_key 
   CONSTRAINT     k   ALTER TABLE ONLY public.share_files_myuser
    ADD CONSTRAINT share_files_myuser_email_key UNIQUE (email);
 Y   ALTER TABLE ONLY public.share_files_myuser DROP CONSTRAINT share_files_myuser_email_key;
       public                 postgres    false    238                       2606    16648 3   share_files_myuser share_files_myuser_google_id_key 
   CONSTRAINT     s   ALTER TABLE ONLY public.share_files_myuser
    ADD CONSTRAINT share_files_myuser_google_id_key UNIQUE (google_id);
 ]   ALTER TABLE ONLY public.share_files_myuser DROP CONSTRAINT share_files_myuser_google_id_key;
       public                 postgres    false    238                       2606    16671 T   share_files_myuser_groups share_files_myuser_groups_myuser_id_group_id_fc552c59_uniq 
   CONSTRAINT     �   ALTER TABLE ONLY public.share_files_myuser_groups
    ADD CONSTRAINT share_files_myuser_groups_myuser_id_group_id_fc552c59_uniq UNIQUE (myuser_id, group_id);
 ~   ALTER TABLE ONLY public.share_files_myuser_groups DROP CONSTRAINT share_files_myuser_groups_myuser_id_group_id_fc552c59_uniq;
       public                 postgres    false    240    240                       2606    16657 8   share_files_myuser_groups share_files_myuser_groups_pkey 
   CONSTRAINT     v   ALTER TABLE ONLY public.share_files_myuser_groups
    ADD CONSTRAINT share_files_myuser_groups_pkey PRIMARY KEY (id);
 b   ALTER TABLE ONLY public.share_files_myuser_groups DROP CONSTRAINT share_files_myuser_groups_pkey;
       public                 postgres    false    240            	           2606    16646 2   share_files_myuser share_files_myuser_phone_no_key 
   CONSTRAINT     q   ALTER TABLE ONLY public.share_files_myuser
    ADD CONSTRAINT share_files_myuser_phone_no_key UNIQUE (phone_no);
 \   ALTER TABLE ONLY public.share_files_myuser DROP CONSTRAINT share_files_myuser_phone_no_key;
       public                 postgres    false    238                       2606    16642 *   share_files_myuser share_files_myuser_pkey 
   CONSTRAINT     m   ALTER TABLE ONLY public.share_files_myuser
    ADD CONSTRAINT share_files_myuser_pkey PRIMARY KEY (user_id);
 T   ALTER TABLE ONLY public.share_files_myuser DROP CONSTRAINT share_files_myuser_pkey;
       public                 postgres    false    238                       2606    16686 b   share_files_myuser_user_permissions share_files_myuser_user__myuser_id_permission_id_e3dd7067_uniq 
   CONSTRAINT     �   ALTER TABLE ONLY public.share_files_myuser_user_permissions
    ADD CONSTRAINT share_files_myuser_user__myuser_id_permission_id_e3dd7067_uniq UNIQUE (myuser_id, permission_id);
 �   ALTER TABLE ONLY public.share_files_myuser_user_permissions DROP CONSTRAINT share_files_myuser_user__myuser_id_permission_id_e3dd7067_uniq;
       public                 postgres    false    242    242                       2606    16664 L   share_files_myuser_user_permissions share_files_myuser_user_permissions_pkey 
   CONSTRAINT     �   ALTER TABLE ONLY public.share_files_myuser_user_permissions
    ADD CONSTRAINT share_files_myuser_user_permissions_pkey PRIMARY KEY (id);
 v   ALTER TABLE ONLY public.share_files_myuser_user_permissions DROP CONSTRAINT share_files_myuser_user_permissions_pkey;
       public                 postgres    false    242            �           2606    16447    users users_auth_id_key 
   CONSTRAINT     U   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_auth_id_key UNIQUE (auth_id);
 A   ALTER TABLE ONLY public.users DROP CONSTRAINT users_auth_id_key;
       public                 postgres    false    218            �           2606    16441    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public                 postgres    false    218            �           2606    16445    users users_google_id_key 
   CONSTRAINT     Y   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_google_id_key UNIQUE (google_id);
 C   ALTER TABLE ONLY public.users DROP CONSTRAINT users_google_id_key;
       public                 postgres    false    218            �           2606    16443    users users_phone_no_key 
   CONSTRAINT     W   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_phone_no_key UNIQUE (phone_no);
 B   ALTER TABLE ONLY public.users DROP CONSTRAINT users_phone_no_key;
       public                 postgres    false    218            �           2606    16474    users users_pkey 
   CONSTRAINT     S   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public                 postgres    false    218            �           1259    16625    auth_group_name_a6ea08ec_like    INDEX     h   CREATE INDEX auth_group_name_a6ea08ec_like ON public.auth_group USING btree (name varchar_pattern_ops);
 1   DROP INDEX public.auth_group_name_a6ea08ec_like;
       public                 postgres    false    226            �           1259    16565 (   auth_group_permissions_group_id_b120cbf9    INDEX     o   CREATE INDEX auth_group_permissions_group_id_b120cbf9 ON public.auth_group_permissions USING btree (group_id);
 <   DROP INDEX public.auth_group_permissions_group_id_b120cbf9;
       public                 postgres    false    228            �           1259    16566 -   auth_group_permissions_permission_id_84c5c92e    INDEX     y   CREATE INDEX auth_group_permissions_permission_id_84c5c92e ON public.auth_group_permissions USING btree (permission_id);
 A   DROP INDEX public.auth_group_permissions_permission_id_84c5c92e;
       public                 postgres    false    228            �           1259    16551 (   auth_permission_content_type_id_2f476e4b    INDEX     o   CREATE INDEX auth_permission_content_type_id_2f476e4b ON public.auth_permission USING btree (content_type_id);
 <   DROP INDEX public.auth_permission_content_type_id_2f476e4b;
       public                 postgres    false    224            �           1259    16581 "   auth_user_groups_group_id_97559544    INDEX     c   CREATE INDEX auth_user_groups_group_id_97559544 ON public.auth_user_groups USING btree (group_id);
 6   DROP INDEX public.auth_user_groups_group_id_97559544;
       public                 postgres    false    232            �           1259    16580 !   auth_user_groups_user_id_6a12ed8b    INDEX     a   CREATE INDEX auth_user_groups_user_id_6a12ed8b ON public.auth_user_groups USING btree (user_id);
 5   DROP INDEX public.auth_user_groups_user_id_6a12ed8b;
       public                 postgres    false    232            �           1259    16595 1   auth_user_user_permissions_permission_id_1fbb5f2c    INDEX     �   CREATE INDEX auth_user_user_permissions_permission_id_1fbb5f2c ON public.auth_user_user_permissions USING btree (permission_id);
 E   DROP INDEX public.auth_user_user_permissions_permission_id_1fbb5f2c;
       public                 postgres    false    234            �           1259    16594 +   auth_user_user_permissions_user_id_a95ead1b    INDEX     u   CREATE INDEX auth_user_user_permissions_user_id_a95ead1b ON public.auth_user_user_permissions USING btree (user_id);
 ?   DROP INDEX public.auth_user_user_permissions_user_id_a95ead1b;
       public                 postgres    false    234            �           1259    16620     auth_user_username_6821ab7c_like    INDEX     n   CREATE INDEX auth_user_username_6821ab7c_like ON public.auth_user USING btree (username varchar_pattern_ops);
 4   DROP INDEX public.auth_user_username_6821ab7c_like;
       public                 postgres    false    230            �           1259    16616 )   django_admin_log_content_type_id_c4bce8eb    INDEX     q   CREATE INDEX django_admin_log_content_type_id_c4bce8eb ON public.django_admin_log USING btree (content_type_id);
 =   DROP INDEX public.django_admin_log_content_type_id_c4bce8eb;
       public                 postgres    false    236            �           1259    16617 !   django_admin_log_user_id_c564eba6    INDEX     a   CREATE INDEX django_admin_log_user_id_c564eba6 ON public.django_admin_log USING btree (user_id);
 5   DROP INDEX public.django_admin_log_user_id_c564eba6;
       public                 postgres    false    236            �           1259    16634 #   django_session_expire_date_a5c62663    INDEX     e   CREATE INDEX django_session_expire_date_a5c62663 ON public.django_session USING btree (expire_date);
 7   DROP INDEX public.django_session_expire_date_a5c62663;
       public                 postgres    false    237            �           1259    16633 (   django_session_session_key_c0390e0f_like    INDEX     ~   CREATE INDEX django_session_session_key_c0390e0f_like ON public.django_session USING btree (session_key varchar_pattern_ops);
 <   DROP INDEX public.django_session_session_key_c0390e0f_like;
       public                 postgres    false    237            �           1259    16669 (   share_files_myuser_auth_id_80170edc_like    INDEX     ~   CREATE INDEX share_files_myuser_auth_id_80170edc_like ON public.share_files_myuser USING btree (auth_id varchar_pattern_ops);
 <   DROP INDEX public.share_files_myuser_auth_id_80170edc_like;
       public                 postgres    false    238                       1259    16666 &   share_files_myuser_email_dc57d9e0_like    INDEX     z   CREATE INDEX share_files_myuser_email_dc57d9e0_like ON public.share_files_myuser USING btree (email varchar_pattern_ops);
 :   DROP INDEX public.share_files_myuser_email_dc57d9e0_like;
       public                 postgres    false    238                       1259    16668 *   share_files_myuser_google_id_b6720986_like    INDEX     �   CREATE INDEX share_files_myuser_google_id_b6720986_like ON public.share_files_myuser USING btree (google_id varchar_pattern_ops);
 >   DROP INDEX public.share_files_myuser_google_id_b6720986_like;
       public                 postgres    false    238                       1259    16684 +   share_files_myuser_groups_group_id_c0732c18    INDEX     u   CREATE INDEX share_files_myuser_groups_group_id_c0732c18 ON public.share_files_myuser_groups USING btree (group_id);
 ?   DROP INDEX public.share_files_myuser_groups_group_id_c0732c18;
       public                 postgres    false    240                       1259    16682 ,   share_files_myuser_groups_myuser_id_71a9c1f1    INDEX     w   CREATE INDEX share_files_myuser_groups_myuser_id_71a9c1f1 ON public.share_files_myuser_groups USING btree (myuser_id);
 @   DROP INDEX public.share_files_myuser_groups_myuser_id_71a9c1f1;
       public                 postgres    false    240                       1259    16683 1   share_files_myuser_groups_myuser_id_71a9c1f1_like    INDEX     �   CREATE INDEX share_files_myuser_groups_myuser_id_71a9c1f1_like ON public.share_files_myuser_groups USING btree (myuser_id varchar_pattern_ops);
 E   DROP INDEX public.share_files_myuser_groups_myuser_id_71a9c1f1_like;
       public                 postgres    false    240                       1259    16667 )   share_files_myuser_phone_no_44febcb7_like    INDEX     �   CREATE INDEX share_files_myuser_phone_no_44febcb7_like ON public.share_files_myuser USING btree (phone_no varchar_pattern_ops);
 =   DROP INDEX public.share_files_myuser_phone_no_44febcb7_like;
       public                 postgres    false    238                       1259    16665 (   share_files_myuser_user_id_3b8722b9_like    INDEX     ~   CREATE INDEX share_files_myuser_user_id_3b8722b9_like ON public.share_files_myuser USING btree (user_id varchar_pattern_ops);
 <   DROP INDEX public.share_files_myuser_user_id_3b8722b9_like;
       public                 postgres    false    238                       1259    16697 6   share_files_myuser_user_permissions_myuser_id_1289e106    INDEX     �   CREATE INDEX share_files_myuser_user_permissions_myuser_id_1289e106 ON public.share_files_myuser_user_permissions USING btree (myuser_id);
 J   DROP INDEX public.share_files_myuser_user_permissions_myuser_id_1289e106;
       public                 postgres    false    242                       1259    16698 ;   share_files_myuser_user_permissions_myuser_id_1289e106_like    INDEX     �   CREATE INDEX share_files_myuser_user_permissions_myuser_id_1289e106_like ON public.share_files_myuser_user_permissions USING btree (myuser_id varchar_pattern_ops);
 O   DROP INDEX public.share_files_myuser_user_permissions_myuser_id_1289e106_like;
       public                 postgres    false    242                       1259    16699 :   share_files_myuser_user_permissions_permission_id_938dd0ef    INDEX     �   CREATE INDEX share_files_myuser_user_permissions_permission_id_938dd0ef ON public.share_files_myuser_user_permissions USING btree (permission_id);
 N   DROP INDEX public.share_files_myuser_user_permissions_permission_id_938dd0ef;
       public                 postgres    false    242            0           2620    16728 #   documents enforce_allowed_file_type    TRIGGER     �   CREATE TRIGGER enforce_allowed_file_type BEFORE INSERT OR UPDATE ON public.documents FOR EACH ROW EXECUTE FUNCTION public.allow_doc_type();
 <   DROP TRIGGER enforce_allowed_file_type ON public.documents;
       public               postgres    false    246    243                       2606    16560 O   auth_group_permissions auth_group_permissio_permission_id_84c5c92e_fk_auth_perm    FK CONSTRAINT     �   ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissio_permission_id_84c5c92e_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;
 y   ALTER TABLE ONLY public.auth_group_permissions DROP CONSTRAINT auth_group_permissio_permission_id_84c5c92e_fk_auth_perm;
       public               postgres    false    224    4825    228                        2606    16555 P   auth_group_permissions auth_group_permissions_group_id_b120cbf9_fk_auth_group_id    FK CONSTRAINT     �   ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_group_id_b120cbf9_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id) DEFERRABLE INITIALLY DEFERRED;
 z   ALTER TABLE ONLY public.auth_group_permissions DROP CONSTRAINT auth_group_permissions_group_id_b120cbf9_fk_auth_group_id;
       public               postgres    false    4830    226    228                       2606    16546 E   auth_permission auth_permission_content_type_id_2f476e4b_fk_django_co    FK CONSTRAINT     �   ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_content_type_id_2f476e4b_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;
 o   ALTER TABLE ONLY public.auth_permission DROP CONSTRAINT auth_permission_content_type_id_2f476e4b_fk_django_co;
       public               postgres    false    222    224    4820            !           2606    16575 D   auth_user_groups auth_user_groups_group_id_97559544_fk_auth_group_id    FK CONSTRAINT     �   ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_group_id_97559544_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id) DEFERRABLE INITIALLY DEFERRED;
 n   ALTER TABLE ONLY public.auth_user_groups DROP CONSTRAINT auth_user_groups_group_id_97559544_fk_auth_group_id;
       public               postgres    false    232    4830    226            "           2606    16570 B   auth_user_groups auth_user_groups_user_id_6a12ed8b_fk_auth_user_id    FK CONSTRAINT     �   ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_user_id_6a12ed8b_fk_auth_user_id FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;
 l   ALTER TABLE ONLY public.auth_user_groups DROP CONSTRAINT auth_user_groups_user_id_6a12ed8b_fk_auth_user_id;
       public               postgres    false    230    4838    232            #           2606    16589 S   auth_user_user_permissions auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm    FK CONSTRAINT     �   ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;
 }   ALTER TABLE ONLY public.auth_user_user_permissions DROP CONSTRAINT auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm;
       public               postgres    false    224    4825    234            $           2606    16584 V   auth_user_user_permissions auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id    FK CONSTRAINT     �   ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;
 �   ALTER TABLE ONLY public.auth_user_user_permissions DROP CONSTRAINT auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id;
       public               postgres    false    4838    230    234            %           2606    16606 G   django_admin_log django_admin_log_content_type_id_c4bce8eb_fk_django_co    FK CONSTRAINT     �   ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_content_type_id_c4bce8eb_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;
 q   ALTER TABLE ONLY public.django_admin_log DROP CONSTRAINT django_admin_log_content_type_id_c4bce8eb_fk_django_co;
       public               postgres    false    222    236    4820            &           2606    16611 B   django_admin_log django_admin_log_user_id_c564eba6_fk_auth_user_id    FK CONSTRAINT     �   ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_user_id_c564eba6_fk_auth_user_id FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;
 l   ALTER TABLE ONLY public.django_admin_log DROP CONSTRAINT django_admin_log_user_id_c564eba6_fk_auth_user_id;
       public               postgres    false    230    4838    236            +           2606    16721     documents documents_org_tag_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_org_tag_fkey FOREIGN KEY (org_tag) REFERENCES public.organization(org_tag);
 J   ALTER TABLE ONLY public.documents DROP CONSTRAINT documents_org_tag_fkey;
       public               postgres    false    217    4802    243            ,           2606    16716 &   documents documents_uploaded_user_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_uploaded_user_fkey FOREIGN KEY (uploaded_user) REFERENCES public.users(user_id);
 P   ALTER TABLE ONLY public.documents DROP CONSTRAINT documents_uploaded_user_fkey;
       public               postgres    false    243    4814    218            -           2606    33131 +   shared_documents fk_share_by_users_to_users    FK CONSTRAINT     �   ALTER TABLE ONLY public.shared_documents
    ADD CONSTRAINT fk_share_by_users_to_users FOREIGN KEY (shared_by_user_id) REFERENCES public.users(user_id);
 U   ALTER TABLE ONLY public.shared_documents DROP CONSTRAINT fk_share_by_users_to_users;
       public               postgres    false    244    218    4814                       2606    16475    users fk_users_to_org    FK CONSTRAINT     �   ALTER TABLE ONLY public.users
    ADD CONSTRAINT fk_users_to_org FOREIGN KEY (org_tag) REFERENCES public.organization(org_tag);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT fk_users_to_org;
       public               postgres    false    218    217    4802            '           2606    16672 N   share_files_myuser_groups share_files_myuser_g_myuser_id_71a9c1f1_fk_share_fil    FK CONSTRAINT     �   ALTER TABLE ONLY public.share_files_myuser_groups
    ADD CONSTRAINT share_files_myuser_g_myuser_id_71a9c1f1_fk_share_fil FOREIGN KEY (myuser_id) REFERENCES public.share_files_myuser(user_id) DEFERRABLE INITIALLY DEFERRED;
 x   ALTER TABLE ONLY public.share_files_myuser_groups DROP CONSTRAINT share_files_myuser_g_myuser_id_71a9c1f1_fk_share_fil;
       public               postgres    false    4875    238    240            (           2606    16677 V   share_files_myuser_groups share_files_myuser_groups_group_id_c0732c18_fk_auth_group_id    FK CONSTRAINT     �   ALTER TABLE ONLY public.share_files_myuser_groups
    ADD CONSTRAINT share_files_myuser_groups_group_id_c0732c18_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id) DEFERRABLE INITIALLY DEFERRED;
 �   ALTER TABLE ONLY public.share_files_myuser_groups DROP CONSTRAINT share_files_myuser_groups_group_id_c0732c18_fk_auth_group_id;
       public               postgres    false    226    240    4830            )           2606    16687 X   share_files_myuser_user_permissions share_files_myuser_u_myuser_id_1289e106_fk_share_fil    FK CONSTRAINT     �   ALTER TABLE ONLY public.share_files_myuser_user_permissions
    ADD CONSTRAINT share_files_myuser_u_myuser_id_1289e106_fk_share_fil FOREIGN KEY (myuser_id) REFERENCES public.share_files_myuser(user_id) DEFERRABLE INITIALLY DEFERRED;
 �   ALTER TABLE ONLY public.share_files_myuser_user_permissions DROP CONSTRAINT share_files_myuser_u_myuser_id_1289e106_fk_share_fil;
       public               postgres    false    238    242    4875            *           2606    16692 \   share_files_myuser_user_permissions share_files_myuser_u_permission_id_938dd0ef_fk_auth_perm    FK CONSTRAINT     �   ALTER TABLE ONLY public.share_files_myuser_user_permissions
    ADD CONSTRAINT share_files_myuser_u_permission_id_938dd0ef_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;
 �   ALTER TABLE ONLY public.share_files_myuser_user_permissions DROP CONSTRAINT share_files_myuser_u_permission_id_938dd0ef_fk_auth_perm;
       public               postgres    false    224    242    4825            .           2606    33121 -   shared_documents shared_documents_doc_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.shared_documents
    ADD CONSTRAINT shared_documents_doc_id_fkey FOREIGN KEY (doc_id) REFERENCES public.documents(doc_id);
 W   ALTER TABLE ONLY public.shared_documents DROP CONSTRAINT shared_documents_doc_id_fkey;
       public               postgres    false    244    4892    243            /           2606    33126 5   shared_documents shared_documents_shared_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.shared_documents
    ADD CONSTRAINT shared_documents_shared_user_id_fkey FOREIGN KEY (shared_user_id) REFERENCES public.users(user_id);
 _   ALTER TABLE ONLY public.shared_documents DROP CONSTRAINT shared_documents_shared_user_id_fkey;
       public               postgres    false    4814    218    244            �      x������ � �      �      x������ � �      �   ,  x�]�[n�0��g{����&��F�
�"����b����3�؟4�`�����n��5���y3�����;�ڔ��Z�T8b�l�˯�#�9����)v0*b���[�nLJi|`K� ꄭd���ΉJR�p�X���{2ҳu7wޣ�ɦ� $�P��X�^�lr
8���|�b| �����<�4:\Vq�s���%�6ySP����2���Cv]<��Oo�yє���Ջ��`��T�;tF����"�Έ�"�M��+*�7�Ω�q&:��nV�9��k6���a����a�      �      x������ � �      �      x������ � �      �      x������ � �      �      x������ � �      �   d   x�M�K
�0Cד��/#H�Q��L���Ep��R�Y��t��}���LNEgUm�h�f��#�����%�tk�D�?` ���/`$=������\L���-3      �   �  x���ݎ� ���)�lÿ�g9	!-�$(.�f���R�u������q`sqc�c��I�  �M4�6 ��@�@zF�鉓N��ZԨ9ޏ"�	0$X����f<� �sy� i]����ྴL�;���}���J_�B�0�.ѸQެ�����%	�E1AIF���3��@�9�A�p��U{H*�����	!g��堾��c���Ca@��[-�(���=(c)wET
�R�R�qSܷ�	��*�nV��͛����3��Ja���l|�[��,���T
���[S�R�\Ut>��k�A���s-8\q|�΁f��A�T����-ႊ��O+��n���p�X0�b���dH�ɻ�Ǧ!��l��!ھ�f��Ϣ�p���7A��
��lY�D�*u����ͱ�q�c]�A)��S۶� &Wg�      �   �   x���
�0 �k����}nmR4"�@tfi�?��=}�F�#٬i�v�R���(����u[|� ]2螇�o�,�T����{�|ʩ�Ou����s�nc5ѹȗW�N6"4A}�O��<�w``6�6x+ �=	��\�lL��A��-F      �   �  x�u��n�@�y
�V����C�11;$h�Q�nc�ىْ���(#��k�_�Q�TBRd����4�`FQj��R[�����T�G�J3���sm�9ȵ���	�M�L8�4	�	�Xz
��	O�eCK- af��PHk�P&h³��Im�'-���O߬|]�"w�kS�[�ܽ���p��p��>Vp��M�nӪ[��m�:��W��%N��������UN.���:��[σv�mb�S����\�� ���$h|�R"ŵA�L) �:A\l�Sޜ�����0�n���u�ZS����A�_�k����i��y���7��g-��Xҡ�!��M5����[�n��դ��� }N��Q�9a���Hu?;��#��@ʪ��/h�3�b���M�m���|ţy&��o�z�̸/��L�./�t�_�z��::�n���$R���@@;��h����a1f���x�*��\��yZ+J���o��h�]ͽ^      �   5  x���ˊ�0�u|�>@R5.-t!À]J��R/$q�"����af5����w(���"�c��q��<�(�R�<=��pa�SB���^[�;��}�P�/طWx�1�	�B7u��2nF~i��˂�d�rGp��L	:g(�V#��D\d)��dRK�Q�@i��L!����� ���C(޴u�.w�xoï4�V��֮٪��7�պ9�3�A8��X�H��<1�$�!TZp4���Q�f_�k��P+��.������B^|v�'t���f�Z����eO{�3��,�G�mE����      �      x������ � �      �      x������ � �      �      x������ � �      �   j   x�-�;�0 ��� �]z�,�8S�JIs�f���7�=4071���ŎT��f��R�:�a�)�#ۃ��XI�(����v�����+���9MCJ�j      �   �   x�m�A��0���ǔ��4�MAQ��a�(�4�6�6K�"��M]v��0�>�LA{d>�ס�����s7cǱ�Q�n=�*�C�YU�Rp��|�)��qjt��g2�"ə�����,r�F�1U��&��8������`��0bބn����U���b9lԤ�hm�k��I��p���9�KX��ąd��������s�$��h^�     