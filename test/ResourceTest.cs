﻿namespace Conjur.Test;

public class ResourceTest : Base
{
    protected readonly string Kind = Constants.KIND_USER;
    protected readonly string Name = "bacon";

    public ResourceTest()
    {
        Client.Authenticator = new MockAuthenticator();
    }

    [Test]
    public async Task TestCheck()
    {
        var resource = Client.Resource(Kind, Name);

        Mocker.Mock(new Uri($"{BaseUri}resources/{TestAccount}/{Kind}/{Name}/?check=true&privilege=fry"), "");
        Assert.IsTrue(resource.Check("fry"));
        Assert.IsTrue(await resource.CheckAsync("fry"));

        Mocker.Mock(new Uri($"{BaseUri}resources/{TestAccount}/{Kind}/{Name}/?check=true&privilege=fry"), "", HttpStatusCode.Forbidden);
        Assert.IsFalse(resource.Check("fry"));
        Assert.IsFalse(await resource.CheckAsync("fry"));
    }

    [Test]
    public void TestNameToId()
    {
        var resource = Client.Resource(Kind, Name);
        Assert.AreEqual($"{Client.AccountName}:{Kind}:{Name}", resource.Id);
    }
}
