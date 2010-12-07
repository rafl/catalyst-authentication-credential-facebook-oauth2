package Catalyst::Authentication::Credential::Facebook::OAuth2;
# ABSTRACT: Authenticate your Catalyst application's users using Facebook's OAuth 2.0

use Moose;
use MooseX::Types::Moose qw(ArrayRef);
use MooseX::Types::Common::String qw(NonEmptySimpleStr);
use aliased 'Net::Facebook::Oauth2', 'OAuth';
use namespace::autoclean;

=head1 SYNOPSIS

    package MyApp;

    __PACKAGE__->config(
        'Plugin::Authentication' => {
            default => {
                credential => {
                    class              => 'Facebook::OAuth2',
                    application_id     => $app_id,
                    application_secret => $app_secret,
                },
                store => { ... },
            },
        },
    );

    ...

    package MyApp::Controller::Foo;

    sub some_action : Local {
        my ($self, $ctx) = @_;

        my $user = $ctx->authenticate({
            scope => ['offline_access', 'publish_stream'],
        });

        # ->authenticate set up a response that'll redirect to Facebook.
        #
        # Wait for the user to tell Facebook to authorise our application
        # by aborting our own request processing with ->detach and simply
        # sending the redirect.
        #
        # Once the user confirmed access for our application, Facebook will
        # redirect back to the URL of this action and ->authenticate will
        # return a valid user retrieved from the user store using the token
        # received from Facebook.
        $ctx->detach unless $user;

        ... # use your $user object (or $ctx->user, or whatever)
    }

=attr application_id

Your application's API key as retrieved from
L<http://www.facebook.com/developers/>.

=attr application_secret

Your application's secret key as retrieved from
L<http://www.facebook.com/developers/>.

=cut

has [qw(application_id application_secret)] => (
    is       => 'ro',
    isa      => NonEmptySimpleStr,
    required => 1,
);

=attr oauth_args

An array reference of additional options to pass to L<Net::Facebook::Oauth2>'s
constructor.

=cut

has oauth_args => (
    is      => 'ro',
    isa     => ArrayRef,
    default => sub { [] },
);

has _oauth => (
    is      => 'ro',
    isa     => OAuth,
    lazy    => 1,
    builder => '_build__oauth',
    handles => {
        (map { ("_${_}" => $_) } qw(get_authorization_url get_access_token)),
    },
);

sub _build__oauth {
    my ($self) = @_;

    return OAuth->new(
        (map { ($_ => $self->$_) } qw(application_id application_secret)),
        @{ $self->oauth_args },
    );
}

sub BUILDARGS {
    my ($self, $config, $ctx, $realm) = @_;

    return $config;
}

sub BUILD {
    my ($self) = @_;

    $self->_oauth;
}

=method authenticate

    my $user = $ctx->authenticate({
        scope => ['offline_access', 'publish_stream'],
    });

Attempts to authenticate a user by using Facebook's OAuth 2.0 interface. This
works by generating an HTTP response that will redirect the user to a page on
L<http://facebook.com> that will ask the user to confirm our request to
authenticate him. Once that has happened, Facebook will redirect back to use and
C<authenticate> will return a user instance.

Note how this is different from most other Catalyst authentication
credentials. Successful authentication requires two requests to the Catalyst
application - one is initiated by the user, the second one is caused by Facebook
redirecting the user back to the application.

Because of that, special care has to be taken. If C<authenticate> returns a
false value, that means it set up the appropriate redirect response in
C<< $ctx->response >>. C<authenticate>'s caller should not manipulate with that
response, but finish his request processing and send the response to the user,
for example by doing C<< $ctx->detach >>.

After being redirected back to from Facebook, C<authenticate> will use the
authentication code Facebook sent back to retrieve an access token from
Facebook. This token will be used to look up a user instance from the
authentication realm's store. That user, or undef if none has been found, will
be returned.

If you're only interested in the access token, you might want to use
L<Catalyst::Authentication::Store::Null> as an authentication store and
introspect the C<token> attribute of the return user instance before logging the
user out again immediately using C<< $ctx->logout >>. You can then later use the
access token you got to communicate with Facebook on behalf of the user that
granted you access.

If access token retrieval fails, an exception will be thrown.

The auth info hash reference passed as the first argument to C<authenticate>
will be passed along to C<Net::Facebook::Oauth2>'s C<get_authorization_url>
method. Please refer to L<Net::Facebook::Oauth2> for details.

=cut

sub authenticate {
    my ($self, $ctx, $realm, $auth_info) = @_;

    unless (defined(my $code = $ctx->request->params->{code})) {
        my $auth_url = $self->_get_authorization_url(
            callback => $ctx->request->uri,
            display  => 'page',
            %{ $auth_info },
        );

        $ctx->response->redirect($auth_url);

        return;
    }
    else {
        my $token = $self->_get_access_token(code => $code);
        die 'Error validating verification code' unless $token;

        return $realm->find_user({
            token => $token,
        }, $ctx);
    }
}

__PACKAGE__->meta->make_immutable;

=head1 ACKNOWLEDGEMENTS

Thanks L<Reask Limited|http://reask.com/> for funding the development of this
module.

=begin Pod::Coverage

  BUILD

=end Pod::Coverage

=cut

1;
