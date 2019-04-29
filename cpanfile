requires 'mro', 0;
requires 'indirect', 0;
requires 'Dir::Self', 0;

requires 'URI', 0;
requires 'URI::QueryParam', 0;
requires 'URI::Template', 0;
requires 'URI::Escape', 0;

requires 'Net::Async::HTTP', 0;
requires 'JSON::MaybeUTF8', 0;

requires 'Ryu::Async', 0;
requires 'IO::Async::Notifier', 0;
requires 'Syntax::Keyword::Try', 0;
requires 'IO::Async::Loop', 0;
requires 'Net::Async::HTTP', 0;
requires 'Path::Tiny', 0;
requires 'HTML::TreeBuilder', 0;
requires 'List::UtilsBy', 0;
requires 'Net::Async::OAuth::Client', 0;

requires 'Log::Any', 0;
requires 'Log::Any::Adapter', 0;

on configure => sub {
    requires 'ExtUtils::MakeMaker', '6.64';
};

on develop => sub {
    requires 'Template', 0;
};

