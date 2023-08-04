function onAlarmMalicious(url) {
  chrome.notifications.create({
    type: "basic",
    title: "URL Checker",
    iconUrl: "alert.png",
    message: "Malicious Website: " + url,
    silent: false,
  });
}

function onAlarmComparison(name) {
  chrome.notifications.create({
    type: "basic",
    title: "URL Checker",
    iconUrl: "alert.png",
    message: "Are you seaching for: " + name,
    silent: false,
  });
}

const layer1 = (domain) => {
  const arr = whitelist.map((a) => a.name);
  // check if the domain is included in the whitelist
  if (!arr.includes(domain)) {
    return false;
  }
  console.log("Verified Website");
  return true;
};

const layer2 = async (domain) => {
  const host = domain;
  const apivoid_key = "39b44ad29fa1d08af9528c0d2bfed00dec6c088e";

  try {
    const response1 = await fetch(
      `https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key=${apivoid_key}&host=${host}`
    );
    const response2 = await fetch(
      `https://endpoint.apivoid.com/domainage/v1/pay-as-you-go/?key=${apivoid_key}&host=${host}`
    );
    const data1 = await response1.json();
    const data2 = await response2.json();
    console.log(data1);
    console.log(data2);

    const score = data1.data?.report.blacklists.detections;
    const age = data2.data?.domain_age_in_days;

    if (score >= 1 || age < 30) {
      console.log("Malicious Website");
      onAlarmMalicious(domain);
      return false;
    }
    return true;
  } catch (error) {
    console.error(error);
  }
};

const layer3 = (domain) => {
  console.log("Comparison Between Domain and Whitelist");

  function comparison(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix = [];

    // initialize the matrix
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    // fill in the matrix
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[b.length][a.length];
  }

  const arr = whitelist.map((a) => a.name);

  for (let i = 0; i < arr.length; i++) {
    const string1 = arr[i];
    const string2 = domain;
    const similarity =
      1 -
      comparison(string1, string2) / Math.max(string1.length, string2.length);
    console.log(`Similarity between ${string1} and ${string2}: ${similarity}`);
    if (similarity >= 0.85 && similarity < 1) {
      console.log("Danger! Similarity Exceed Threshold Value!");
      onAlarmComparison(string1);
      break;
    }
  }
};

chrome.tabs.onActivated.addListener((tabs) => {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    let url = tabs[0].url;
    console.log("The current URL is: " + url);
    let domain = url.split("//")[1].split("/")[0].split(":")[0];
    console.log(domain);

    let result = false;
    result = layer1(domain);
    // if (!result) layer2(domain);
    if (!result) layer3(domain);
  });
});

const whitelist = [
  {
    name: "www.amazon.com",
  },
  {
    name: "www.netflix.com",
  },
  {
    name: "www.facebook.com",
  },
  {
    name: "www.twitter.com",
  },
  {
    name: "www.instagram.com",
  },
  {
    name: "www.linkedin.com",
  },
  {
    name: "www.youtube.com",
  },
  {
    name: "www.google.com",
  },
  {
    name: "zoom.us",
  },
  {
    name: "www.yahoo.com",
  },
  {
    name: "outlook.live.com",
  },
  {
    name: "www.apple.com",
  },
  {
    name: "www.spotify.com",
  },
  {
    name: "www.pinterest.com",
  },
  {
    name: "www.figma.com",
  },
  {
    name: "www.freepik.com",
  },
  {
    name: "www.blogger.com",
  },
  {
    name: "www.reddit.com",
  },
  {
    name: "www.quora.com",
  },
  {
    name: "www.github.com",
  },
  {
    name: "www.stackoverflow.com",
  },
  {
    name: "shopee.com.my",
  },
  {
    name: "www.lazada.com.my",
  },
  {
    name: "www.zalora.com.my",
  },
  {
    name: "www.alibaba.com",
  },
  {
    name: "www.aliexpress.com",
  },
  {
    name: "www.ebay.com",
  },
  {
    name: "www.expedia.com",
  },
  {
    name: "www.booking.com",
  },
  {
    name: "www.airasia.com",
  },
  {
    name: "www.malaysiaairlines.com",
  },
  {
    name: "www.tripadvisor.com",
  },
  {
    name: "www.hotels.com",
  },
  {
    name: "www.agoda.com",
  },
  {
    name: "www.airbnb.com",
  },
  {
    name: "www.twitch.tv",
  },
  {
    name: "www.cimbclicks.com.my",
  },
  {
    name: "www.maybank2u.com.my",
  },
  {
    name: "www.pbebank.com",
  },
  {
    name: "www.airbnb.com",
  },
  {
    name: "www.uobgroup.com",
  },
  {
    name: "www.dbs.com.sg",
  },
  {
    name: "www.wikipedia.org",
  },
  {
    name: "www.espn.com",
  },
  {
    name: "www.nba.com",
  },
  {
    name: "www.fifa.com",
  },
  {
    name: "www.nationalgeographic.com",
  },
  {
    name: "www.bbc.com",
  },
  {
    name: "www.nytimes.com",
  },
  {
    name: "www.nike.com",
  },
  {
    name: "www.adidas.com.my",
  },
  {
    name: "www.jobstreet.com.my",
  },
  {
    name: "www.mudah.my",
  },
  {
    name: "www.carousell.com.my",
  },
  {
    name: "www.maxis.com.my",
  },
  {
    name: "www.digi.com.my",
  },
  {
    name: "unifi.com.my",
  },
  {
    name: "www.gsc.com.my",
  },
  {
    name: "www.tgv.com.my",
  },
  {
    name: "chat.openai.com",
  },
];
