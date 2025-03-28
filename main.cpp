class Solution {
public:
    
    int jobScheduling(vector<int>& startTime, vector<int>& endTime, vector<int>& profit) {
        vector<tuple<int,int, int>> sortedJobs;
        for(int i = 0; i<startTime.size(); ++i){
            sortedJobs.push_back({endTime[i], startTime[i], profit[i]});
        }        
        sort(sortedJobs.begin(), sortedJobs.end());
        
        vector<int>dp;
        
        for(auto c: sortedJobs){
            dp.push_back(get<2>(c));
        }

        for(int i = 1; i<endTime.size(); ++i){
             int latestNonConflictJobIndex = upper_bound(sortedJobs.begin(), sortedJobs.begin() + i-1, startTime, [&](int time, const auto& job) ->     bool {return time < get<0>(job);}) - sortedJobs.begin();
            if(index != -1){
                dp[i] = max(dp[i], dp[latestNonConflictJobIndex] + dp[i]);
            }
        }
        return *max_element(dp.begin(), dp.end());
    }
};
