using Conjur.JWTProviders;

namespace Conjur.Test;

public class JWTAuthenticatorTest : Base
{
    private const string ServiceId = "sid";
    private const string HostId = "hid";
    private readonly ConstantJWTProvider jwtProvider = new("this is a nice provider");
    private JWTAuthenticator authenticator;

    [SetUp]
    public void CreateAuthenticator()
    {
        authenticator = new JWTAuthenticator(Client, jwtProvider, ServiceId, HostId);
    }

    [Test]
    public async Task TestWithoutHostId()
    {
        authenticator = new JWTAuthenticator(Client, jwtProvider, ServiceId);

        MockToken("token1", null);
        Assert.AreEqual("token1", authenticator.GetToken());

        await MockTokenExpirationAsync();

        MockAsyncToken("token2", null);
        Assert.AreEqual("token2", await authenticator.GetTokenAsync());
    }

    [Test]
    public void TestTokenCaching()
    {
        MockToken("token1");
        Assert.AreEqual("token1", authenticator.GetToken());
        MockToken("token2");

        Assert.AreEqual("token1", authenticator.GetToken());
        MockTokenExpiration();
        Assert.AreEqual("token2", authenticator.GetToken());
    }

    [Test]
    public async Task TestTokenCachingAsync()
    {
        MockAsyncToken("token1");
        Assert.AreEqual("token1", await authenticator.GetTokenAsync());
        MockAsyncToken("token2");

        Assert.AreEqual("token1", await authenticator.GetTokenAsync());
        await MockTokenExpirationAsync();
        Assert.AreEqual("token2", await authenticator.GetTokenAsync());
    }

    [Test]
    public void TestTokenThreadSafe()
    {
        var authenticationCount = 0;
        var token = "token1";

        MockToken(token).Verifier = Verifier;

        Assert.AreEqual(token, authenticator.GetToken());
        Assert.AreEqual(1, authenticationCount);

        var t1 = new Thread(Checker);
        var t2 = new Thread(Checker);

        t1.Start(token); t2.Start(token);
        t1.Join(); t2.Join();

        Assert.AreEqual(1, authenticationCount);

        MockTokenExpiration();

        token = "token2";
        MockToken(token).Verifier = Verifier;

        t1 = new Thread(Checker);
        t2 = new Thread(Checker);

        Assert.AreEqual(1, authenticationCount);
        t1.Start(token); t2.Start(token);
        t1.Join(); t2.Join();
        Assert.AreEqual(2, authenticationCount);

        void Verifier(HttpRequestMessage requestMessage)
        {
            JwtContentVerifier(requestMessage);
            Thread.Sleep(10);
            Interlocked.Increment(ref authenticationCount);
        }

        void Checker(object expected)
        {
            Assert.AreEqual(expected, authenticator.GetToken());
        }
    }

    [Test]
    public async Task TestTokenThreadSafeAsync()
    {
        var authenticationCount = 0;
        var token = "token1";

        MockAsyncToken(token).VerifierAsync = VerifierAsync;

        Assert.AreEqual(token, await authenticator.GetTokenAsync());
        Assert.AreEqual(1, authenticationCount);

        var tasks = CreateTasks(token);

        MockAsyncToken("fake").VerifierAsync = VerifierAsync;

        await Task.WhenAll(tasks);

        Assert.AreEqual(1, authenticationCount);

        await MockTokenExpirationAsync();

        token = "token2";
        MockAsyncToken(token).VerifierAsync = VerifierAsync;

        tasks = CreateTasks(token);

        await Task.WhenAll(tasks);
        Assert.AreEqual(2, authenticationCount);

        await MockTokenExpirationAsync();

        token = "token3";
        MockAsyncToken(token).VerifierAsync = VerifierAsync;

        tasks = [.. Enumerable.Range(0, 20).Select(_ => Checker(token))];

        await Task.WhenAll(tasks);
        Assert.AreEqual(3, authenticationCount);

        async Task VerifierAsync(HttpRequestMessage requestMessage)
        {
            await JwtContentVerifierAsync(requestMessage);
            await Task.Delay(50);
            Interlocked.Increment(ref authenticationCount);
        }

        async Task<string> Checker(string expected)
        {
            var actual = await authenticator.GetTokenAsync();
            Assert.AreEqual(expected, actual);
            return actual;
        }
        Task<string>[] CreateTasks(string expected) =>
        [
            Checker(expected),
            Checker(expected),
            Checker(expected),
            Task.Run(() =>
            {
                var actual = authenticator.GetToken();
                Assert.AreEqual(expected, actual);
                return actual;
            }),
            Checker(expected),
        ];
    }

    private static void JwtContentVerifier(HttpRequestMessage requestMessage)
    {
        Assert.AreEqual(HttpMethod.Post, requestMessage.Method);
        Assert.AreEqual("jwt=this+is+a+nice+provider", requestMessage.Content!.ReadAsStringAsync().Result);
    }

    private static async Task JwtContentVerifierAsync(HttpRequestMessage requestMessage)
    {
        Assert.AreEqual(HttpMethod.Post, requestMessage.Method);
        Assert.AreEqual("jwt=this+is+a+nice+provider", await requestMessage.Content!.ReadAsStringAsync());
    }

    private WebMocker.MockResponse MockToken(string token, string hostId = HostId)
    {
        hostId = string.IsNullOrEmpty(hostId) ? hostId : hostId + "/";
        var mock = Mocker.Mock(new Uri($"test://example.com/authn-jwt/{ServiceId}/{TestAccount}/{hostId}authenticate"), token);
        mock.Verifier = JwtContentVerifier;
        return mock;
    }

    private WebMocker.MockResponse MockAsyncToken(string token, string hostId = HostId)
    {
        var mock = MockToken(token, hostId);
        mock.VerifierAsync = JwtContentVerifierAsync;
        return mock;
    }

    protected void MockTokenExpiration()
    {
        authenticator.StartTokenTimer(new TimeSpan(0, 0, 0, 0, 1));
        Thread.Sleep(20);
        Thread.Yield();
    }

    protected async Task MockTokenExpirationAsync()
    {
        authenticator.StartTokenTimer(new TimeSpan(0, 0, 0, 0, 1));
        await Task.Delay(20);
    }
}
